from platform import Platform
from dotenv import load_dotenv
import os

load_dotenv()

servers = []
apis = []
certs = []

i = 1
while True:
    server = os.getenv(f'SERVER_{i}')
    if server is None:
        break
    cert = os.getenv(f'CERT_{i}')
    if cert is None:
        break
    api = os.getenv(f'API_{i}')
    if api is None:
        break
    servers += [server]
    apis += [api]
    certs += [cert]
    i += 1

print(servers)
print(apis)
print(certs)

platform = Platform(servers, apis, certs)
print(platform)

print('-----Platfrom initialized-----\n')

current_users = platform.user_dict
print(f'Found {len(current_users)} users\n')
for user_name in current_users.keys():
    print(current_users[user_name])

print('\n-----Adding users-----\n\n')
users_to_register = ['User1', 'User2', 'User3', 'User4']

for i, user in enumerate(users_to_register):
    platform.create_new_key(user, limit_value=(i + 5) * 1000 * 1000)


current_users = platform.user_dict
print(f'Found {len(current_users)} users\n')
for user_name in current_users.keys():
    print(current_users[user_name])

print('\n-----Setting new limits-----\n\n')
for i, user in enumerate(users_to_register):
    print('Old: ' + platform.get_key(user).__str__())
    print('data from get_balance: ', end='')
    print(platform.get_balance(user))

    platform.set_limit(user, 10 * (i + 5) * 1000 * 1000)
    print('New: '+ platform.get_key(user).__str__())
    print('data from get_balance: ', end='')
    print(platform.get_balance(user))

    platform.bump_limit(user, 123)
    print('After bump: ' + platform.get_key(user).__str__())
    print('data from get_balance: ', end='')
    print(platform.get_balance(user))

print('\n-----Removing users-----\n\n')

for i, user in enumerate(users_to_register):
    platform.remove_user(user)

current_users = platform.user_dict
print(f'Found {len(current_users)} users\n')
for user_name in current_users.keys():
    print(current_users[user_name])