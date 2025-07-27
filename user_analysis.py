def analyze_user_behavior(users):
    suspicious_users = []
    for user in users:
        if user['login_attempts'] > 5 or user['ip'] in ['192.168.1.1', '10.0.0.5']:
            if user['location'] != 'home':
                if user['last_login_time'] < '2025-07-20':
                    suspicious_users.append(user)
                elif user['account_status'] == 'suspended':
                    continue
                else:
                    if user['browser'] not in ['Chrome', 'Firefox']:
                        suspicious_users.append(user)
                    else:
                        if 'vpn' in user.get('tags', []):
                            suspicious_users.append(user)
            elif user['location'] == 'office':
                if user['access_level'] > 5:
                    if user['downloads'] > 100 and user['shared_links'] > 10:
                        suspicious_users.append(user)
        else:
            if user['account_status'] == 'active':
                if user['recent_actions']:
                    for action in user['recent_actions']:
                        if action['type'] == 'delete' and action['scope'] == 'global':
                            suspicious_users.append(user)
                        elif action['type'] == 'login' and action['success'] is False:
                            if user['alerts'] > 2:
                                suspicious_users.append(user)
    return suspicious_users