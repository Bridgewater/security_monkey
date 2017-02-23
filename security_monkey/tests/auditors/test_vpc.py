#     Copyright 2016 Bridgewater Associates
#
#     Licensed under the Apache License, Version 2.0 (the "License");
#     you may not use this file except in compliance with the License.
#     You may obtain a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#     Unless required by applicable law or agreed to in writing, software
#     distributed under the License is distributed on an "AS IS" BASIS,
#     WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#     See the License for the specific language governing permissions and
#     limitations under the License.
"""
.. module: security_monkey.tests.test_vpc
    :platform: Unix
.. version:: $$VERSION$$
.. moduleauthor:: Bridgewater OSS <opensource@bwater.com>
"""
from security_monkey.tests import SecurityMonkeyTestCase
from security_monkey.auditors.vpc.vpc import VPCAuditor
from security_monkey.watchers.vpc.flow_log import FlowLog


class MockVPCObj:
    def __init__(self):
        self.config = {}
        self.audit_issues = []
        self.index = "unittestindex"
        self.region = "unittestregion"
        self.account = "unittestaccount"
        self.name = "unittestname"

class MockFlowLogObj:
    def __init__(self):
        self.name = "unittestflowlog"
        self.index = FlowLog.index
        self.account = "unittestaccount"
        self.config = {
            "resource_id": "NOTmockvpcid"
        }

class VPCAuditorTestCase(SecurityMonkeyTestCase):
    def test_flow_logs_enabled(self):
        auditor = VPCAuditor(accounts=['unittestaccount'])
        vpcobj = MockVPCObj()
        flowlogobj = MockFlowLogObj()
        auditor.current_slurped_items = {
            (flowlogobj.account + FlowLog.index): [flowlogobj]
        }

        vpcobj.config = {"id": "mockvpcid"}

        self.assertIs(
            expr1=len(vpcobj.audit_issues),
            expr2=0,
            msg="VPC should have 0 alert but has {}".format(len(vpcobj.audit_issues)))
        auditor.check_flow_logs_enabled(vpcobj)
        self.assertIs(
            expr1=len(vpcobj.audit_issues),
            expr2=1,
            msg="VPC should have 1 alert but has {}".format(len(vpcobj.audit_issues)))