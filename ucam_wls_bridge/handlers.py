from typing import Any, Dict, List

from . import User


# https://help.uis.cam.ac.uk/service/accounts-passwords/it-staff/university-central-directory/understanding-users-and-groups#central-groups
GROUP_UOC_ALUMNI = "bc7a045e-6775-423a-abc6-deac53b50712"
GROUP_UOC_CURRENT = "b7a0f932-5964-41b2-9bb0-9b8cadf6b999"

def uoc_groups(user: Dict[str, Any]) -> User:
    try:
        upn: str = user["preferred_username"]
        groups: List[str] = user["groups"]
    except KeyError:
        raise LookupError("Missing username or groups in user info")
    if GROUP_UOC_CURRENT in groups and upn.endswith("@cam.ac.uk"):
        return upn.split("@", 1)[0], ["current"]
    elif GROUP_UOC_ALUMNI in groups and upn.endswith("@cantab.ac.uk"):
        return upn.split("@", 1)[0], []
    else:
        raise LookupError("Unable to derive CRSid from authentication")
