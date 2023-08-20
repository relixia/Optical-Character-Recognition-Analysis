from cache.redis_conf import redis_client

def cache_result(key, result):
    redis_client.set(key, result)

def get_cached_result(key):
    cached_result = redis_client.get(key)
    return cached_result.decode('utf-8') if cached_result else None
