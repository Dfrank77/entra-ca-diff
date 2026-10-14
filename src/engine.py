from models import ConditionalAccessPolicyModel

class CADiffEngine:
    @staticmethod
    def evaluate(old_raw: dict, new_raw: dict) -> list[str]:
        alerts = []
        
        # Instantiate and strictly validate data contracts using Pydantic
        old_policy = ConditionalAccessPolicyModel.model_validate(old_raw)
        new_policy = ConditionalAccessPolicyModel.model_validate(new_raw)
        
        # Rule 1: Guardrail enforcement state downshifting
        if old_policy.state == "enabled" and new_policy.state != "enabled":
            alerts.append(
                f"⚠️ STATE DOWNGRADE: Policy '{old_policy.display_name}' changed from "
                f"'enabled' to '{new_policy.state}'."
            )
            
        # Rule 2: Complete removal of standard MFA enforcement
        old_controls = old_policy.grant_controls.built_in_controls if old_policy.grant_controls else []
        new_controls = new_policy.grant_controls.built_in_controls if new_policy.grant_controls else []
        
        if "mfa" in old_controls and "mfa" not in new_controls:
            alerts.append(
                f"🚨 SECURITY RETRACTION: MFA control mechanism was explicitly removed "
                f"from policy '{old_policy.display_name}'."
            )
            
        # Rule 3: Evaluation of critical user exclusions ("All" bypass safety)
        old_exclude_users = old_policy.conditions.users.exclude_users if old_policy.conditions.users else []
        new_exclude_users = new_policy.conditions.users.exclude_users if new_policy.conditions.users else []
        
        if "All" in new_exclude_users and "All" not in old_exclude_users:
            alerts.append(
                f"💥 CRITICAL CONFIGURATION FAULT: 'All' users string has been added to exclusions "
                f"on policy '{old_policy.display_name}'. This bypasses policy rules globally."
            )
            
        return alerts
