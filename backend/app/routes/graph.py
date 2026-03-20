from fastapi import APIRouter, Depends

from app.core.rbac import require_role
from app.db.mongo import get_database
from app.schemas.asset import GraphResponse
from app.schemas.auth import CurrentUser

router = APIRouter()


@router.get("/graph", response_model=GraphResponse)
async def get_graph(_: CurrentUser = Depends(require_role("admin", "viewer"))):
    db = get_database()
    assets = await db.assets.find({}).to_list(length=200)
    nodes = []
    edges = []

    for asset in assets:
        asset_id = str(asset.get("_id", asset.get("host", "unknown")))
        nodes.append(
            {
                "id": asset_id,
                "label": asset.get("host", asset_id),
                "type": asset.get("type", "subdomain"),
                "highest_severity": asset.get("highest_severity"),
                "ip_addresses": asset.get("ip_addresses", []),
            }
        )
        parent = asset.get("parent")
        if parent:
            edges.append({"source": parent, "target": asset_id})

    return GraphResponse(nodes=nodes, edges=edges)
