//

package controllers

import (
	"context"
	"fmt"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/util/intstr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/controller/controllerutil"
	"sigs.k8s.io/controller-runtime/pkg/log"
)

var operatorLabels = labels.Set{
	vars.AppNameLabel:      vars.Instana,
	vars.AppComponentLabel: vars.Operator,
}

func (r *BaseReconciler) reconcileDNSNetworkPolicy(ctx context.Context, owner client.Object) error {
	nm := networkpolicy.MutatorFromObjectKey(client.ObjectKey{
		Namespace: owner.GetNamespace(),
		Name:      owner.GetName() + "-dns",
	})
	tcp := corev1.ProtocolTCP
	udp := corev1.ProtocolUDP
	var dnsPort int32 = 53
	opts := append([]networkpolicy.Opt{},
		networkpolicy.Labels(operatorLabels),
		networkpolicy.EmptyPodSelector(),
		networkpolicy.AddPolicyType(v1.PolicyTypeEgress),
		networkpolicy.AddEgressRule(
			[]v1.NetworkPolicyPort{
				{
					Protocol: &tcp,
					Port: &intstr.IntOrString{
						Type:   intstr.Int,
						IntVal: dnsPort,
					},
				},
				{
					Protocol: &udp,
					Port: &intstr.IntOrString{
						Type:   intstr.Int,
						IntVal: dnsPort,
					},
				},
			},
			nil,
		),
	)

	networkPolicy := nm.Apply(opts...)
	return r.reconcileNetworkPolicy(ctx, owner, networkPolicy)
}

func (r *BaseReconciler) reconcileAgentNetworkPolicy(ctx context.Context, owner client.Object) error {
	nm := networkpolicy.MutatorFromObjectKey(client.ObjectKey{
		Namespace: owner.GetNamespace(),
		Name:      owner.GetName() + "-agent",
	})
	opts := append([]networkpolicy.Opt{},
		networkpolicy.Labels(operatorLabels),
		networkpolicy.PodSelector(labels.Set{
			vars.AppNameLabel:      vars.Instana,
			vars.InstanaGroupLabel: vars.Service,
		}),
		networkpolicy.AddPolicyType(v1.PolicyTypeEgress),
	)

	nodeList := &corev1.NodeList{}
	if err := r.List(ctx, nodeList); err != nil {
		return err
	}
	for _, node := range nodeList.Items {
		for _, address := range node.Status.Addresses {
			if address.Type == corev1.NodeInternalIP {
				opts = append(opts, networkpolicy.AddEgressRule(nil,
					[]v1.NetworkPolicyPeer{
						{
							IPBlock: &v1.IPBlock{
								CIDR: address.Address + "/32",
							},
						},
					}))
				break
			}
		}
	}

	networkPolicy := nm.Apply(opts...)
	return r.reconcileNetworkPolicy(ctx, owner, networkPolicy)
}

func (r *BaseReconciler) reconcileHazelcastNetworkPolicy(ctx context.Context, owner client.Object) error {
	nm := networkpolicy.MutatorFromObjectKey(client.ObjectKey{
		Namespace: owner.GetNamespace(),
		Name:      owner.GetName() + "-hazelcast",
	})
	opts := append([]networkpolicy.Opt{},
		networkpolicy.Labels(operatorLabels),
		networkpolicy.PodSelector(labels.Set{
			vars.AppNameLabel:      vars.Instana,
			vars.InstanaGroupLabel: vars.Service,
		}),
		networkpolicy.AddPolicyType(v1.PolicyTypeIngress),
		networkpolicy.AddPolicyType(v1.PolicyTypeEgress),
	)

	tcp := corev1.ProtocolTCP
	policyPorts := []v1.NetworkPolicyPort{
		{
			Protocol: &tcp,
			Port: &intstr.IntOrString{
				Type:   intstr.Int,
				IntVal: 5701,
			},
		},
	}
	policyPeers := []v1.NetworkPolicyPeer{
		{
			PodSelector: &metav1.LabelSelector{},
		},
	}
	opts = append(opts,
		networkpolicy.AddIngressRule(policyPorts, policyPeers),
		networkpolicy.AddEgressRule(policyPorts, policyPeers),
	)

	apiServerEndpointsKey := client.ObjectKey{
		Namespace: "default",
		Name:      "kubernetes",
	}

	addresses, err := objectutils.LookupEndpointsAddresses(ctx, r, apiServerEndpointsKey)
	if err != nil {
		return err
	}
	policyPeers = []v1.NetworkPolicyPeer{}
	for _, address := range addresses {
		policyPeers = append(policyPeers, v1.NetworkPolicyPeer{
			IPBlock: &v1.IPBlock{
				CIDR: address + "/32",
			},
		})
	}

	ports, err := objectutils.LookupEndpointsPorts(ctx, r, apiServerEndpointsKey)
	if err != nil {
		return err
	}
	policyPorts = []v1.NetworkPolicyPort{}
	for _, port := range ports {
		policyPorts = append(policyPorts, v1.NetworkPolicyPort{
			Protocol: &tcp,
			Port: &intstr.IntOrString{
				Type:   intstr.Int,
				IntVal: port,
			},
		})
	}

	opts = append(opts,
		networkpolicy.AddEgressRule(policyPorts, policyPeers),
	)

	networkPolicy := nm.Apply(opts...)
	return r.reconcileNetworkPolicy(ctx, owner, networkPolicy)
}

func (r *BaseReconciler) reconcileOperatorNetworkPolicy(ctx context.Context) error {
	if vars.IsTestMode() {
		log.FromContext(ctx).V(logging.Warn).Info("skip installing netpol for operator in test mode")
		return nil
	}

	list := &appsv1.DeploymentList{}
	if err := r.List(ctx, list, client.InNamespace(r.OperatorNamespace), client.MatchingLabels(operatorLabels)); err != nil {
		return err
	}

	if length := len(list.Items); length != 1 {
		return fmt.Errorf("expected to find 1 operator deployment but found %d", length)
	}
	owner := list.Items[0]
	key := client.ObjectKeyFromObject(&owner)

	nm := networkpolicy.MutatorFromObjectKey(key)
	opts := append([]networkpolicy.Opt{},
		networkpolicy.Labels(operatorLabels),
		networkpolicy.PodSelector(operatorLabels),
		networkpolicy.AddPolicyType(v1.PolicyTypeEgress),
		networkpolicy.AddEgressRule(nil, []v1.NetworkPolicyPeer{
			{
				IPBlock: &v1.IPBlock{
					CIDR: "0.0.0.0/0",
				},
			},
		}),
	)

	apiServerEndpointsKey := client.ObjectKey{
		Namespace: "default",
		Name:      "kubernetes",
	}

	addresses, err := objectutils.LookupEndpointsAddresses(ctx, r, apiServerEndpointsKey)
	if err != nil {
		return err
	}
	var policyPeers []v1.NetworkPolicyPeer
	for _, address := range addresses {
		policyPeers = append(policyPeers, v1.NetworkPolicyPeer{
			IPBlock: &v1.IPBlock{
				CIDR: address + "/32",
			},
		})
	}

	tcp := corev1.ProtocolTCP
	policyPorts := []v1.NetworkPolicyPort{
		{
			Protocol: &tcp,
			Port: &intstr.IntOrString{
				Type:   intstr.Int,
				IntVal: vars.WebhookServerPort,
			},
		},
	}

	// Access from API server for webhook calls
	opts = append(opts, networkpolicy.AddIngressRule(policyPorts, policyPeers))

	networkPolicy := nm.Apply(opts...)
	return r.reconcileNetworkPolicy(ctx, &owner, networkPolicy)
}

func (r *BaseReconciler) reconcileNetworkPolicy(ctx context.Context, owner client.Object, desired *v1.NetworkPolicy) error {
	logger := log.FromContext(ctx).WithValues("networkpolicy", desired.GetName())

	observed := networkpolicy.FromObjectKey(client.ObjectKeyFromObject(desired))
	if _, err := ctrl.CreateOrUpdate(ctx, r.Client, observed, func() error {
		logger.V(logging.Debug).Info("Reconciling")

		if err := mergo.Merge(observed, desired, mergo.WithOverride); err != nil {
			return err
		}

		if metav1.HasLabel(desired.ObjectMeta, vars.InstanaTenantUnitLabel) {
			if err := controllerutil.SetControllerReference(owner, observed, r.Scheme); err != nil {
				return err
			}
		} else {
			// We can't set controller ref because a controller ref can only be set for one controller,
			// whereas an object can have multiple owner refs. This applies to ui-client.
			if err := controllerutil.SetOwnerReference(owner, observed, r.Scheme); err != nil {
				return err
			}
		}
		return nil
	}); err != nil {
		return err
	}
	return nil
}

func (r *BaseReconciler) reconcileNetworkPolicies(ctx context.Context, owner client.Object, netpolComps []components.Component, allComps []components.Component, dsConfigs v1beta2.DatastoreConfigs) error {
	logger := log.FromContext(ctx)

	if err := r.reconcileDNSNetworkPolicy(ctx, owner); err != nil {
		return err
	}
	if err := r.reconcileAgentNetworkPolicy(ctx, owner); err != nil {
		return err
	}
	if err := r.reconcileHazelcastNetworkPolicy(ctx, owner); err != nil {
		return err
	}
	if err := r.reconcileOperatorNetworkPolicy(ctx); err != nil {
		return err
	}

	for _, sourceComp := range netpolComps {
		key := sourceComp.GetObjectKey()
		if _, isUnit := owner.(*v1beta2.Unit); isUnit {
			if !sourceComp.GetLabels().Has(vars.InstanaTenantUnitLabel) {
				// This is the case for ui-client and ingress, which are neither core nor unit components,
				// but installed in the unit namespace.
				// We need to add a suffix to get distinct netpols per tenant
				key.Name = fmt.Sprintf("%s-%s", key.Name, owner.GetName())
			}
		}
		nm := networkpolicy.MutatorFromObjectKey(key)

		var opts []networkpolicy.Opt
		opts = append(opts,
			networkpolicy.Labels(sourceComp.GetLabels()),
			networkpolicy.PodSelector(sourceComp.GetLabels()),
			networkpolicy.AddPolicyType(v1.PolicyTypeEgress),
			networkpolicy.AddPolicyType(v1.PolicyTypeIngress),
		)

		// TODO global butler

		// general ingress
		settings := sourceComp.GetComponentSettings()
		if settings.Ingress {
			// ingress from outside the cluster
			opts = append(opts, networkpolicy.AddIngressRule(networkpolicy.NamedTCPPortsToNetworkPolicyPorts(settings.Ports), []v1.NetworkPolicyPeer{
				{
					IPBlock: &v1.IPBlock{
						CIDR: "0.0.0.0/0",
					},
				},
			}))
			// ingress from inside the cluster
			opts = append(opts, networkpolicy.AddIngressRule(networkpolicy.NamedTCPPortsToNetworkPolicyPorts(settings.Ports), []v1.NetworkPolicyPeer{
				{
					PodSelector: &metav1.LabelSelector{},
				},
			}))
		}

		// egress to other pods
		for _, egress := range settings.EgressRules {
			target := egress.Target
			targetType := egress.TargetType

			switch targetType {
			case config.TargetComponent:
				// We have multiple components with the same name if there are multiple units for a core.
				targetComps := components.GetComponentsByName(allComps, target)
				if len(targetComps) == 0 {
					logger.V(logging.Debug).Info("egress to unknown component", "source", sourceComp.GetName(), "target", target)
				}
				for _, targetComp := range targetComps {
					// egress to unit pods in the same namespace
					opts = append(opts, networkpolicy.AddEgressRule(networkpolicy.NamedTCPPortsToNetworkPolicyPorts(egress.GetPortNames()),
						[]v1.NetworkPolicyPeer{
							{
								NamespaceSelector: metav1.SetAsLabelSelector(labels.Set{
									vars.AppNameLabel: targetComp.GetObjectKey().Namespace,
								}),
								PodSelector: metav1.SetAsLabelSelector(targetComp.GetLabels()),
							},
						},
					))
				}
			case config.TargetDatabase:
				var cfg *v1beta2.DatastoreConfig
				switch target {
				case "ingress":
					cfg = &dsConfigs.KafkaConfig.DatastoreConfig
				case "beemetrics":
					if dsConfigs.BeeInstanaConfig != nil {
						cfg = &dsConfigs.BeeInstanaConfig.DatastoreConfig
					}
				case "metadata_ng":
					if dsConfigs.ElasticsearchConfig != nil {
						cfg = &dsConfigs.ElasticsearchConfig.DatastoreConfig
					}
				default:
					var err error
					cfg, err = func() (*v1beta2.DatastoreConfig, error) {
						for _, cfg := range dsConfigs.CassandraConfigs {
							for _, keyspace := range cfg.Keyspaces {
								if target == keyspace {
									return &cfg.DatastoreConfig, nil
								}
							}
						}
						for _, cfg := range dsConfigs.ClickhouseConfigs {
							for _, schema := range cfg.Schemas {
								if target == schema {
									return &cfg.DatastoreConfig, nil
								}
							}
						}
						for _, cfg := range dsConfigs.PostgresConfigs {
							for _, database := range cfg.Databases {
								if target == database {
									return &cfg.DatastoreConfig, nil
								}
							}
						}
						return nil, fmt.Errorf("unknown netpol datastore target: %s", target)
					}()
					if err != nil {
						return err
					}
				}

				if cfg != nil {
					var hostPorts []net.HostPort
					addresses := cfg.Hosts
					ports := cfg.Ports
					for _, address := range addresses {
						for _, port := range ports {
							hostPorts = append(hostPorts, net.HostPort{
								Host: address,
								Port: port.Port,
							})
						}
					}
					opts = append(opts, networkpolicy.AddEgressRule(k8s.NetworkPolicyPortsFromHostPorts(hostPorts), k8s.NetworkPolicyPeersFromHostPorts(hostPorts)))
				}
			case config.TargetExternal:
				// for now, we allow egress to the world for external egress
				opts = append(opts, networkpolicy.AddEgressRule(nil, []v1.NetworkPolicyPeer{
					{
						IPBlock: &v1.IPBlock{
							CIDR: "0.0.0.0/0",
						},
					},
				}))
				// for now, we allow egress to everything within the cluster, in case DBs are run in the cluster
				opts = append(opts, networkpolicy.AddEgressRule(nil, []v1.NetworkPolicyPeer{
					{
						PodSelector: &metav1.LabelSelector{},
					},
				}))
			}
		}

		// ingress from other pods
		for _, ingress := range settings.IngressRules {
			target := ingress.Target
			targetType := ingress.TargetType

			switch targetType {
			case config.TargetComponent:
				targetComps := components.GetComponentsByName(allComps, target)
				if len(targetComps) == 0 {
					logger.V(logging.Debug).Info("ingress from unknown component", "source", sourceComp.GetName(), "target", target)
				}
				for _, targetComp := range targetComps {
					// ingress from pods in the same namespace
					opts = append(opts, networkpolicy.AddIngressRule(networkpolicy.NamedTCPPortsToNetworkPolicyPorts(ingress.GetPortNames()),
						[]v1.NetworkPolicyPeer{
							{
								NamespaceSelector: metav1.SetAsLabelSelector(labels.Set{
									vars.AppNameLabel: targetComp.GetObjectKey().Namespace,
								}),
								PodSelector: metav1.SetAsLabelSelector(targetComp.GetLabels()),
							},
						},
					))
				}
			default:
				return fmt.Errorf("unsupported target type for ingress rule: %s", targetType)
			}
		}

		// ingress from operator
		opts = append(opts, networkpolicy.AddIngressRule(
			networkpolicy.NamedTCPPortsToNetworkPolicyPorts([]string{
				config.ServicePort.Name,
				config.AdminPort.Name,
			}),
			[]v1.NetworkPolicyPeer{
				{
					NamespaceSelector: metav1.SetAsLabelSelector(labels.Set{
						vars.AppNameLabel: r.OperatorNamespace,
					}),
					PodSelector: metav1.SetAsLabelSelector(operatorLabels),
				},
			},
		))

		networkPolicy := nm.Apply(opts...)
		if err := r.reconcileNetworkPolicy(ctx, owner, networkPolicy); err != nil {
			return err
		}
	}

	return nil
}

func (r *CoreReconciler) removeObsoleteNetworkPolicies(ctx context.Context, core *v1beta2.Core) error {
	unitList, err := apiutils.FindUnitsByCore(ctx, r.Client, core)
	if err != nil {
		return err
	}

	namespaces := []string{core.Namespace}
	for _, unit := range unitList {
		namespaces = util.AppendIfMissing(namespaces, unit.Namespace)
	}

	for _, namespace := range namespaces {
		if err := r.DeleteAllOf(ctx, &v1.NetworkPolicy{}, client.InNamespace(namespace), client.MatchingLabels{
			vars.AppNameLabel: vars.Instana,
		}); err != nil {
			return err
		}
	}

	var hasCoreWithNetpolsEnabled bool
	cores, err := apiutils.FindCores(ctx, r)
	if err != nil {
		return err
	}
	for _, core := range cores {
		if core.Spec.EnableNetworkPolicies {
			hasCoreWithNetpolsEnabled = true
			break
		}
	}
	if !hasCoreWithNetpolsEnabled {
		// We can only delete the operator network policy if there is no more core that has network policies enabled
		if err := r.DeleteAllOf(ctx, &v1.NetworkPolicy{}, client.InNamespace(r.OperatorNamespace), client.MatchingLabels(operatorLabels)); err != nil {
			return err
		}
	}
	return nil
}
