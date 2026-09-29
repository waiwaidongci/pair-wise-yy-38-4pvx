from __future__ import annotations
from .domain import ConflictError, ValidationError
TITLE='水库防汛调度与操作确认'; ENTITY='调度指令'; ID_PREFIX='RF'
SNAPSHOT_ENTITY='水情快照'; IDEM_ENTITY='幂等提交'
SEVERITIES=['routine', 'attention', 'urgent', 'emergency']; STATES=['draft', 'checked', 'authorized', 'executed', 'closed']; TRANSITIONS={'draft': ['checked'], 'checked': ['authorized'], 'authorized': ['executed'], 'executed': ['closed'], 'closed': []}; TRANSITION_ROLES={'checked': ['duty_officer'], 'authorized': ['chief_engineer'], 'executed': ['dispatcher'], 'closed': ['chief_engineer']}
CREATE_ROLES=set(['duty_officer']); RECORD_ROLES=set(['duty_officer', 'dispatcher']); AUDIT_ROLES=set(['chief_engineer', 'viewer']); VIEW_ROLES=set(['duty_officer', 'chief_engineer', 'dispatcher', 'viewer']); SNAPSHOT_ROLES=set(['duty_officer', 'chief_engineer'])
SEVERITY_WEIGHT={'routine': 1.0, 'attention': 3.0, 'urgent': 6.0, 'emergency': 9.0}; DEADLINE_HOURS={'routine': 72, 'attention': 24, 'urgent': 8, 'emergency': 4}; TERMINAL_STATES=set(['closed'])
INVALIDATABLE_STATES=tuple(['checked', 'authorized']); SNAPSHOT_FIELD_LABELS={'water_level': '库位', 'inflow': '入库流量', 'downstream_alert': '下游警戒', 'construction_limits': '施工限制'}
def priority_score(severity,quantity=0.0,threshold=1.0,open_records=0):
    if severity not in SEVERITY_WEIGHT: raise ValidationError("unknown severity")
    ratio=quantity/threshold if threshold>0 else 1.0
    return max(0,min(10,int(round(SEVERITY_WEIGHT[severity]+min(4.0,ratio*4.0)+min(3.0,float(open_records))))))
def response_deadline_hours(severity,quantity=0.0,threshold=1.0):
    if severity not in DEADLINE_HOURS: raise ValidationError("unknown severity")
    ratio=quantity/threshold if threshold>0 else 1.0
    return max(1,int(DEADLINE_HOURS[severity]/max(1.0,ratio)))
def escalation_required(severity,quantity=0.0,threshold=1.0):
    return severity==SEVERITIES[-1] or (threshold>0 and quantity>=threshold)
def can_transition(current,target): return target in TRANSITIONS.get(current,[])
def validate_transition(current,target):
    if current not in STATES or target not in STATES: raise ValidationError("未知状态")
    if not can_transition(current,target): raise ConflictError(f"不能从{current}转换到{target}")
def completion_blockers(target,open_records): return ["仍有未关闭事项"] if target in TERMINAL_STATES and open_records>0 else []
def snapshot_blockers(target,item_snapshot_version,current_snapshot_version):
    if target=='authorized' and item_snapshot_version!=current_snapshot_version:
        return [f"快照已更新（指令基于v{item_snapshot_version}，当前v{current_snapshot_version}），授权失效需重新复核"]
    return []
def invalidation_reason(new_version,changed_fields):
    labels=[SNAPSHOT_FIELD_LABELS.get(f,f) for f in changed_fields]
    cause='、'.join(labels)+'变化' if labels else '重新采样'
    return f"水情快照v{new_version}已发布（{cause}），旧授权失效退回待复核"
def role_for_transition(target): return set(TRANSITION_ROLES.get(target,[]))
