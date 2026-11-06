"""Route trusted, server-assigned log sources without trusting request contents."""
import re


def local_agent_ids(value):
    """Parse the administrator's comma-separated source IDs into a stable list."""
    if isinstance(value, str):
        values = value.split(',')
    elif isinstance(value, list) and all(isinstance(item, str) for item in value):
        values = value
    else:
        raise ValueError('本地规则 Agent ID 应为逗号分隔文本或字符串列表。')
    result = []
    for item in values:
        item = item.strip()
        if not item:
            continue
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}', item):
            raise ValueError('本地规则 Agent ID 格式不正确。')
        if item not in result:
            result.append(item)
    if len(','.join(result)) > 4000:
        raise ValueError('本地规则 Agent ID 列表过长。')
    return result


def is_local_source(config, record):
    if config.get('analysisMode') == 'local':
        return True
    # These fields come from the database envelope or normalized_event(), never raw JSON.
    if 'source_type' in record:
        source, agent_id = record.get('source_type'), record.get('agent_id')
    else:
        source, agent_id = record.get('_source_type'), record.get('_agent_id')
    return source == 'agent' and bool(agent_id) and agent_id in config.get('localAgentIds', [])
