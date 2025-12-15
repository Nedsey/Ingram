"""根据指纹给出目标产品信息"""
import hashlib
import re
import requests

from loguru import logger
from lxml import etree


def _build_response_context(req):
    """Cache expensive response parsing for reuse across fingerprint rules."""
    context = {
        'md5': None,
        'title': '',
        'body': '',
        'headers': '',
    }

    try:
        context['md5'] = hashlib.md5(req.content).hexdigest()
    except Exception:
        pass

    try:
        html = etree.HTML(req.text) if req.text else None
        if html is not None:
            titles = html.xpath('//title')
            if titles:
                context['title'] = titles[0].xpath('string(.)').lower()
            bodies = html.xpath('//body')
            if bodies:
                context['body'] = ' '.join(
                    node.xpath('string(.)') for node in bodies[0]
                ).lower()
    except Exception:
        pass

    try:
        context['headers'] = ' '.join(
            ''.join(item).lower() for item in req.headers.items()
        )
    except Exception:
        pass

    return context


def _parse(req, rule_val, context):
    """判断 requests 返回值是否符合指纹规则
    rule_val 可能是多种规则的且关系: xxx&&xxx...
    """
    def check_one(item):
        left, right = re.search(r'(.*)=`(.*)`', item).groups()
        right_lower = right.lower()

        if left == 'md5':
            return context['md5'] == right
        if left == 'title':
            return right_lower in context['title']
        if left == 'body':
            return right_lower in context['body']
        if left == 'headers':
            return right_lower in context['headers']
        if left == 'status_code':
            return int(req.status_code) == int(right)
        return False

    return all(map(check_one, rule_val.split('&&')))


def fingerprint(ip, port, config):
    req_dict = {}  # 暂存 requests 的返回值
    responses_to_close = []
    session = requests.session()
    adapter = requests.adapters.HTTPAdapter(
        pool_connections=config.th_num,
        pool_maxsize=config.th_num * 2,
    )
    session.mount('http://', adapter)
    headers = {'Connection': 'close', 'User-Agent': config.user_agent}

    try:
        for path, rules in config.rules_by_path.items():
            try:
                cached_req = req_dict.get(path)
                if cached_req is not None:
                    req, context = cached_req
                else:
                    req = session.get(f"http://{ip}:{port}{path}", headers=headers, timeout=config.timeout)
                    responses_to_close.append(req)
                    context = _build_response_context(req)
                    if req.status_code == 200:
                        req_dict[path] = (req, context)

                for rule in rules:
                    if _parse(req, rule.val, context):
                        return rule.product
            except Exception as e:
                logger.error(e)
        return None
    finally:
        for resp in responses_to_close:
            try:
                resp.close()
            except Exception:
                pass
        session.close()
