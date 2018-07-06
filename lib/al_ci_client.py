from CIAuth import CIAuth

class CloudInsight(CIAuth):
    def __init__(self, args):
        self.service = "launcher"
        CIAuth.__init__(self,args)

    def get_launcher_status(self):
        self.service = "launcher"
        return self.query(self.service, [self.account_id, "environments", self.environment_id])

    def get_launcher_resource(self):
        self.service = "launcher"
        return self.query(self.service, [self.account_id, "resources"])

    def get_environments(self):
        self.service = "environments"
        return self.query(self.service, [self.account_id, self.environment_id])

    def get_environments_by_cid(self):
        self.service = "environments"
        return self.query(self.service, [self.account_id])

    def get_environments_by_cid_custom(self, query_args=None):
        self.service = "environments"
        return self.query(self.service, [self.account_id], query_args)

    def get_asset_custom(self, query_args=None):
        self.service = "assets"
        return self.query(self.service, [self.account_id, "environments", self.environment_id, "assets"], query_args)

    def get_remediations(self):
        self.service = "assets"
        return self.query(self.service, [self.account_id, "environments", self.environment_id, "remediations"])

    def get_remediations_short(self):
        self.service = "assets"
        query_args={}
        query_args['include_filters'] = 'false'
        query_args['include_remediations'] = 'true'
        query_args['details'] = 'false'
        return self.query(self.service, [self.account_id, "environments", self.environment_id, "remediations"], query_args)

    def get_remediations_custom(self, query_args=None):
        self.service = "assets"
        return self.query(self.service, [self.account_id, "environments", self.environment_id, "remediations"], query_args)

    def get_all_child(self):
        #curl -X GET -H "Accept: application/json" -H $AL_TOKEN_HEADER "https://api.cloudinsight.alertlogic.com/aims/v1/$PARENTCID/accounts/managed?active=true" | jq "."
        self.service = "aims"
        query_args={}
        query_args['active'] = 'true'
        return self.query(self.service, [self.account_id, "accounts", "managed"], query_args)

    def get_vulnerability_map(self):
        self.service = "vulnerability"
        return self.query(self.service, [])

    def get_scheduler_summary(self):
        self.service = "scheduler"
        return self.query(self.service, [self.account_id, self.environment_id, "summary"])
