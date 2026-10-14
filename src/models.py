from typing import List, Optional
from pydantic import BaseModel, Field

class CAUsersCondition(BaseModel):
    include_users: List[str] = Field(default_factory=list, alias="includeUsers")
    exclude_users: List[str] = Field(default_factory=list, alias="excludeUsers")
    include_groups: List[str] = Field(default_factory=list, alias="includeGroups")
    exclude_groups: List[str] = Field(default_factory=list, alias="excludeGroups")
    include_roles: List[str] = Field(default_factory=list, alias="includeRoles")
    exclude_roles: List[str] = Field(default_factory=list, alias="excludeRoles")

class CAApplicationsCondition(BaseModel):
    include_applications: List[str] = Field(default_factory=list, alias="includeApplications")
    exclude_applications: List[str] = Field(default_factory=list, alias="excludeApplications")

class CAConditionSet(BaseModel):
    users: Optional[CAUsersCondition] = None
    applications: Optional[CAApplicationsCondition] = None

class CAGrantControls(BaseModel):
    operator: Optional[str] = None
    built_in_controls: List[str] = Field(default_factory=list, alias="builtInControls")

class ConditionalAccessPolicyModel(BaseModel):
    id: Optional[str] = None
    display_name: str = Field(..., alias="displayName")
    state: str  # enabled, disabled, enabledForReportingButNotEnforced
    conditions: CAConditionSet
    grant_controls: Optional[CAGrantControls] = Field(None, alias="grantControls")

    class Config:
        populate_by_name = True
