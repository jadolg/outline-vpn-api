from outline_vpn import OutlineVPN
import random
import datetime


class Platform:
    def __init__(self, servers, apis, certs):
        self.servers = servers  # server names
        self.apis = apis  # API keys received from Outline server
        self.certs = certs  # certificates received from Outline server

        self.vpn_servers = []  # list of OutlineVPN client objects
        self.user_dict = {}  # dict with users' keys

        # initialize the servers
        for i in range(len(servers)):
            vpn_server = OutlineVPN(api_url=apis[i], cert_sha256=certs[i])
            self.vpn_servers += [vpn_server]

        # load the actual (last created for each user) keys from the servers
        self.load_keys()

    def load_keys(self, server_id=None):
        user_dict_list = {}  # temporary dict of lists to get all existing keys and then keep only last created per user
        for i, vpn_server in enumerate(self.vpn_servers):
            if server_id is not None:
                if i != server_id:
                    continue
            keys = vpn_server.get_keys()
            if keys is not None:
                for key in keys:
                    # ignoring any not standartized names like "{username string},{datetime like %Y-%m-%d %H:%M:%S}"
                    if Platform.check_name(key.name):
                        str_user_name = Platform.get_user_name(key.name)
                        if str_user_name in user_dict_list.keys():
                            user_dict_list[str_user_name] += [Key(key, i)]
                        else:
                            user_dict_list[str_user_name] = [Key(key, i)]

        # to ensure the following correct work we need to remove the old keys
        for str_user_id in user_dict_list.keys():
            if len(user_dict_list[str_user_id]) > 1:
                keys = user_dict_list[str_user_id]
                dates = [self.get_date(k.name) for k in keys]

                sorted_keys = [x for _, x in sorted(zip(dates, keys), key=lambda pair: pair[0])]
                keep_key = sorted_keys[-1]
                to_remove_keys = sorted_keys[:-1]
                for key in to_remove_keys:
                    self.vpn_servers[key.server_id].delete_key(key.key_id)
                self.user_dict[str_user_id] = keep_key
            else:
                self.user_dict[str_user_id] = user_dict_list[str_user_id][0]

    @staticmethod
    def is_valid_date(date_string):
        try:
            datetime.datetime.strptime(date_string, "%Y-%m-%d %H:%M:%S")
            return True
        except ValueError:
            return False

    @staticmethod
    def check_name(name):
        len_ = len(name.split(','))
        if len_ == 2:
            dt = name.split(',')[1]
            if Platform.is_valid_date(dt):
                return True
            else:
                return False
        else:
            return False

    @staticmethod
    def get_date(name):
        return name.split(',')[1]

    @staticmethod
    def get_user_name(name):
        return name.split(',')[0]

    def get_key(self, str_user_id):
        if str_user_id in self.user_dict.keys():
            return self.user_dict[str_user_id]
        else:
            return None

    def remove_user(self, str_user_id):
        if str_user_id in self.user_dict.keys():
            key = self.user_dict[str_user_id]
            del self.user_dict[str_user_id]  # remove from cached (soft delete)
            self.vpn_servers[key.server_id].delete_key(key.key_id)  # hard delete can fail

    def get_balance(self, str_user_id):
        if str_user_id in self.user_dict.keys():
            key = self.user_dict[str_user_id]
            self.load_keys(server_id=key.server_id)

            key = self.user_dict[str_user_id]
            return key.used_bytes, key.data_limit
        else:
            return None, None

    def set_limit(self, str_user_id, limit_value):
        if str_user_id in self.user_dict.keys():
            key = self.user_dict[str_user_id]
            result = self.vpn_servers[key.server_id].add_data_limit(key.key_id, limit_value)
            if result:
                key.data_limit = limit_value
                self.user_dict[str_user_id] = key
                return True
            else:
                return False
        else:
            return False

    def bump_limit(self, str_user_id, addition_value):
        used, data_limit = self.get_balance(str_user_id)
        if used is None:
            return False  # User not found
        else:
            key = self.user_dict[str_user_id]
            data_limit_new = data_limit + addition_value
            result = self.vpn_servers[key.server_id].add_data_limit(key.key_id, data_limit_new)
            if result:
                key.data_limit = data_limit_new
                self.user_dict[str_user_id] = key
                return True
            else:
                return False

    def create_new_key(self, str_user_id, limit_value=None, forced_server_id=None):
        # forced_server_id is an integer to choose which server id to use
        last_server_id = -1
        if str_user_id in self.user_dict.keys():
            key = self.user_dict[str_user_id]

            last_server_id = key.server_id
            self.vpn_servers[key.server_id].delete_key(key.key_id)

        if forced_server_id is None:
            if last_server_id == -1:
                new_server_id = random.randint(0, len(self.vpn_servers) - 1)
            else:
                new_server_id = (last_server_id + 1) % len(self.vpn_servers)
        else:
            new_server_id = forced_server_id

        now = datetime.datetime.now()
        now_str = now.strftime("%Y-%m-%d %H:%M:%S")

        key = self.vpn_servers[new_server_id].create_key(str_user_id+','+now_str)
        if limit_value is not None:
            self.vpn_servers[new_server_id].add_data_limit(key.key_id, limit_value)

        new_key = Key(key, new_server_id)
        new_key.data_limit = limit_value
        self.user_dict[str_user_id] = new_key

        return new_key

    def __str__(self):
        print_line = f"Number of servers is {len(self.vpn_servers)}:\n"
        for i in range(len(self.vpn_servers)):
            print_line += f"-{self.servers[i]}\n"
        return print_line


class Key:
    def __init__(self, key, server_id):
        self.key_id = key.key_id
        self.name = key.name
        self.password = key.password
        self.port = key.port
        self.method = key.method
        self.access_url = key.access_url
        self.used_bytes = 0 if key.used_bytes is None else key.used_bytes
        self.data_limit = key.data_limit  # might be None
        self.server_id = server_id

    def __str__(self):
        return f"server #{self.server_id+1}, key_id {self.key_id}, name={self.name}, used_mb={self.used_bytes/1000000}, data_limit_mb={self.data_limit/1000000}"
