using System;
using NetFwTypeLib;

namespace VPN
{
    public class Firewall
    {

        public static void BlockIPInFirewall(string sourceIP)
        {
            const string ruleName = "Block Malicious IP";

            string blockRange;
            if (sourceIP.Contains("."))
            {
                blockRange = sourceIP.Substring(0, sourceIP.LastIndexOf('.')) + ".0/24";
            }
            else
            {
                blockRange= sourceIP.Substring(0, sourceIP.LastIndexOf(':')) + ":0/112";
            }



            var firewallRule = GetFirewallRule(ruleName);
            if (firewallRule == null)
            {
                INetFwPolicy2 fwPolicy2 = (INetFwPolicy2)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2"));
                var currentProfiles = fwPolicy2.CurrentProfileTypes;

                // Let's create a new rule

                INetFwRule2 inboundRule = (INetFwRule2)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FWRule"));
                inboundRule.Name = ruleName;
                inboundRule.Enabled = true;
                inboundRule.Protocol = 6; // TCP
                inboundRule.RemoteAddresses = blockRange;
                inboundRule.Action = NET_FW_ACTION_.NET_FW_ACTION_BLOCK;

                inboundRule.Profiles = currentProfiles;


                fwPolicy2.Rules.Add(inboundRule);
            }
            else
            {
                firewallRule.RemoteAddresses += "," + blockRange;
            }



        }

        private static INetFwRule GetFirewallRule(string ruleName)
        {
            var fwPolicy2 = (INetFwPolicy2)Activator.CreateInstance(Type.GetTypeFromProgID("HNetCfg.FwPolicy2"));


            foreach (INetFwRule rule in fwPolicy2.Rules)
            {
                // Add rule to list
                //RuleList.Add(rule);
                // Console.WriteLine(rule.Name);
                if (rule.Name == ruleName)
                {
                    return rule;
                }
            }

            return null;
        }
    }
}