"""Small-cluster feasibility for the vendor's public zone YAML representation."""
import itertools
import math

from cluster import UnsafeState, arguments, database_container, flag_value


def matches(tokens, node):
    for token in tokens:
        if not isinstance(token,str) or len(token)<2 or token[0] not in '+-':
            raise UnsafeState('unsupported placement constraint representation')
        key, equals, value = token[1:].partition('=')
        present = node['locality'].get(key)==value if equals else key in node['attrs']
        if present != (token[0]=='+'):return False
    return True


def satisfied(config, nodes, count):
    if config is None:return True
    if isinstance(config,list):return all(matches(config,node) for node in nodes)
    if not isinstance(config,dict):raise UnsafeState('unsupported placement constraint representation')
    groups=[]
    for conjunction, demand in config.items():
        if not isinstance(conjunction,str) or not isinstance(demand,int) or demand<1:
            raise UnsafeState('unsupported counted placement constraint')
        groups.append((conjunction.split(','),demand))
    total=sum(demand for _,demand in groups)
    if total>count:return False
    if any(sum(matches(tokens,node) for node in nodes)<demand for tokens,demand in groups):return False
    return total<count or all(any(matches(tokens,node) for tokens,_ in groups) for node in nodes)


def feasible(config, nodes, replicas, voters):
    if not 1<=voters<=replicas<=len(nodes):return False
    if math.comb(len(nodes),replicas)*math.comb(replicas,voters)>100000:
        raise UnsafeState('placement inspection exceeds bounded small-cluster search')
    for chosen in itertools.combinations(nodes,replicas):
        if not satisfied(config.get('constraints',[]),chosen,replicas):continue
        for voting in itertools.combinations(chosen,voters):
            if satisfied(config.get('voter_constraints',[]),voting,voters):return True
    return False


def selected_nodes(cluster):
    rows={row['id']:row for row in cluster.node_rows() if row.get('membership')!='decommissioned'}
    result=[]
    for ordinal,pod in enumerate(cluster.pods(cluster.statefulset())):
        db=database_container({'spec':pod['spec']})
        tokens=arguments(db)
        stores=[t.split('=',1)[1] for t in tokens if t.startswith(('--store=','-s='))]
        stores += [t[2:] for t in tokens if t.startswith('-s') and not t.startswith('-s=') and t!='-s']
        stores += [tokens[i+1] for i,t in enumerate(tokens[:-1]) if t in ('--store','-s')]
        if len(stores)>1:raise UnsafeState('placement repair requires one understood store per selected node')
        attrs=flag_value(db,'--attrs','')
        options=dict(p.split('=',1) for p in (stores or [''])[0].split(',') if '=' in p)
        store_attrs=options.get('attrs','')
        if any(char in attrs+store_attrs for char in '$`'):
            raise UnsafeState('placement attributes require literal startup values')
        row=rows[cluster.node_id(ordinal)]
        locality={}
        for tier in filter(None,row.get('locality','').split(',')):
            key,equals,value=tier.partition('=')
            if not equals or key in locality:raise UnsafeState('native node locality is ambiguous')
            locality[key]=value
        result.append({'locality':locality,'attrs':set(filter(None,(attrs+':'+store_attrs).split(':')))})
    return result
