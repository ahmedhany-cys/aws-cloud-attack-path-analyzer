"""EC2 part of the read-only collector: instances, security groups and routing.

Shares the stubbed-session plumbing of ``test_aws_inventory``; no credentials file and no
network are used.
"""

from __future__ import annotations

from typing import Any

import pytest

from tests.unit.test_aws_inventory import (
    ACCOUNT,
    REGION,
    Clients,
    authorization_page,
    build_clients,
    coverage,
    role_detail,
    stub_identity,
)


@pytest.fixture
def clients(monkeypatch: pytest.MonkeyPatch) -> Clients:
    return build_clients(monkeypatch)


PROFILE_ARN = f"arn:aws:iam::{ACCOUNT}:instance-profile/web"
ROLE_ARN = f"arn:aws:iam::{ACCOUNT}:role/service-role/web"
VPC = "vpc-0123456789abcdef0"


def instance(
    instance_id: str,
    *,
    subnet: str,
    public_ip: str | None = None,
    tokens: str | None = "required",
    profile: str | None = None,
    groups: tuple[str, ...] = ("sg-web",),
    state: str = "running",
) -> dict[str, Any]:
    item: dict[str, Any] = {
        "InstanceId": instance_id,
        "State": {"Code": 16 if state == "running" else 80, "Name": state},
        "SubnetId": subnet,
        "VpcId": VPC,
        "SecurityGroups": [{"GroupId": g, "GroupName": g} for g in groups],
        "Tags": [{"Key": "Name", "Value": f"name-{instance_id[-1]}"}],
    }
    if public_ip:
        item["PublicIpAddress"] = public_ip
        item["PublicDnsName"] = f"ec2-{public_ip.replace('.', '-')}.compute.amazonaws.com"
    if tokens is not None:
        item["MetadataOptions"] = {
            "State": "applied",
            "HttpTokens": tokens,
            "HttpPutResponseHopLimit": 1,
            "HttpEndpoint": "enabled",
        }
    if profile:
        item["IamInstanceProfile"] = {"Arn": profile, "Id": "AIPAEXAMPLE000000001"}
    return item


def security_group(group_id: str, *permissions: dict[str, Any]) -> dict[str, Any]:
    return {
        "GroupId": group_id,
        "GroupName": group_id,
        "Description": f"group {group_id}",
        "OwnerId": ACCOUNT,
        "VpcId": VPC,
        "IpPermissions": list(permissions),
        "Tags": [{"Key": "env", "Value": "test"}],
    }


def permission(
    protocol: str,
    port: int | None = None,
    *,
    cidrs: tuple[str, ...] = (),
    ipv6: tuple[str, ...] = (),
    groups: tuple[str, ...] = (),
    prefix_lists: tuple[str, ...] = (),
) -> dict[str, Any]:
    item: dict[str, Any] = {
        "IpProtocol": protocol,
        "IpRanges": [{"CidrIp": c, "Description": "rule"} for c in cidrs],
        "Ipv6Ranges": [{"CidrIpv6": c} for c in ipv6],
        "UserIdGroupPairs": [{"GroupId": g, "UserId": ACCOUNT} for g in groups],
        "PrefixListIds": [{"PrefixListId": p} for p in prefix_lists],
    }
    if port is not None:
        item["FromPort"] = item["ToPort"] = port
    return item


def route_tables() -> dict[str, Any]:
    return {
        "RouteTables": [
            {
                "RouteTableId": "rtb-main",
                "VpcId": VPC,
                "Associations": [
                    {
                        "Main": True,
                        "RouteTableAssociationId": "rtbassoc-main",
                        "RouteTableId": "rtb-main",
                        "AssociationState": {"State": "associated"},
                    }
                ],
                "Routes": [
                    {
                        "DestinationCidrBlock": "10.0.0.0/16",
                        "GatewayId": "local",
                        "State": "active",
                        "Origin": "CreateRouteTable",
                    }
                ],
            },
            {
                "RouteTableId": "rtb-public",
                "VpcId": VPC,
                "Associations": [
                    {
                        "Main": False,
                        "RouteTableAssociationId": "rtbassoc-public",
                        "RouteTableId": "rtb-public",
                        "SubnetId": "subnet-public",
                        "AssociationState": {"State": "associated"},
                    }
                ],
                "Routes": [
                    {
                        "DestinationCidrBlock": "10.0.0.0/16",
                        "GatewayId": "local",
                        "State": "active",
                    },
                    {
                        "DestinationCidrBlock": "0.0.0.0/0",
                        "GatewayId": "igw-0123",
                        "State": "active",
                    },
                ],
            },
        ]
    }


def stub_iam_with_instance_profile(clients: Clients) -> None:
    profile = {
        "Path": "/",
        "InstanceProfileName": "web",
        "InstanceProfileId": "AIPAEXAMPLE000000001",
        "Arn": PROFILE_ARN,
        "CreateDate": "2025-01-10T09:00:00Z",
        "Roles": [],
    }
    clients["iam"].add_response(
        "get_account_authorization_details",
        authorization_page(roles=[role_detail("web", InstanceProfileList=[profile])]),
        {},
    )


def test_instances_security_groups_and_routing_become_snapshot_fields(clients: Clients) -> None:
    stub_identity(clients)
    stub_iam_with_instance_profile(clients)
    ec2 = clients["ec2"]
    ec2.add_response(
        "describe_instances",
        {
            "Reservations": [
                {
                    "ReservationId": "r-1",
                    "OwnerId": ACCOUNT,
                    "Instances": [
                        instance(
                            "i-0000000000000000a",
                            subnet="subnet-public",
                            public_ip="203.0.113.10",
                            tokens="optional",
                            profile=PROFILE_ARN,
                        ),
                        instance("i-0000000000000000b", subnet="subnet-private", groups=("sg-db",)),
                    ],
                }
            ],
            "NextToken": "page-2",
        },
        {},
    )
    ec2.add_response(
        "describe_instances",
        {
            "Reservations": [
                {
                    "ReservationId": "r-2",
                    "OwnerId": ACCOUNT,
                    "Instances": [
                        instance(
                            "i-0000000000000000c",
                            subnet="subnet-public",
                            public_ip="203.0.113.11",
                            tokens=None,
                            profile=f"arn:aws:iam::{ACCOUNT}:instance-profile/unlisted",
                            state="stopped",
                        )
                    ],
                }
            ]
        },
        {"NextToken": "page-2"},
    )
    ec2.add_response(
        "describe_security_groups",
        {
            "SecurityGroups": [
                security_group(
                    "sg-web",
                    permission("tcp", 443, cidrs=("0.0.0.0/0",), ipv6=("::/0",)),
                    permission("tcp", 22, cidrs=("198.51.100.0/24",)),
                    permission("-1", groups=("sg-db",)),
                    permission("tcp", 8080, prefix_lists=("pl-0123",)),
                    permission("udp", 53),  # no source at all: skipped
                ),
                security_group("sg-db", permission("tcp", 5432, groups=("sg-web",))),
            ]
        },
        {},
    )
    ec2.add_response("describe_route_tables", route_tables(), {})

    snapshot = clients.collector(services=("iam", "ec2")).collect()
    clients.assert_all_consumed()

    web, worker, stopped = snapshot["ec2_instances"]
    assert web["arn"] == f"arn:aws:ec2:{REGION}:{ACCOUNT}:instance/i-0000000000000000a"
    assert web["name"] == "name-a" and web["state"] == "running"
    assert web["public_ip"] == "203.0.113.10" and web["internet_facing"] is True
    assert web["role_arn"] == ROLE_ARN and web["instance_profile_arn"] == PROFILE_ARN
    assert web["imdsv2_required"] is False and web["security_groups"] == ["sg-web"]
    assert worker["public_ip"] is None and worker["internet_facing"] is False
    assert worker["role_arn"] is None and worker["imdsv2_required"] is True
    assert stopped["state"] == "stopped" and stopped["imdsv2_required"] is None
    assert stopped["role_arn"] is None and stopped["instance_profile_arn"].endswith("/unlisted")

    groups = {g["group_id"]: g for g in snapshot["security_groups"]}
    assert set(groups) == {"sg-web", "sg-db"}
    rules = groups["sg-web"]["ingress"]
    assert [r["protocol"] for r in rules] == ["tcp", "tcp", "all", "tcp"]
    assert rules[0] == {
        "protocol": "tcp",
        "cidrs": ["0.0.0.0/0"],
        "ipv6_cidrs": ["::/0"],
        "source_groups": [],
        "from_port": 443,
        "to_port": 443,
        "description": "rule",
    }
    assert rules[2]["source_groups"] == ["sg-db"] and "from_port" not in rules[2]
    assert rules[3]["source_groups"] == ["pl-0123"]

    ec2_coverage = coverage(snapshot, "ec2")
    # One instance profile was not listed with a role, so the inventory is partial, not complete.
    assert ec2_coverage["status"] == "partial"
    assert any("unlisted" in note for note in ec2_coverage["notes"])
    assert any("region" in note and "EC2" in note for note in snapshot["coverage"]["notes"])


def test_denied_instance_listing_marks_ec2_missing(clients: Clients) -> None:
    stub_identity(clients)
    clients["ec2"].add_client_error(
        "describe_instances",
        service_error_code="UnauthorizedOperation",
        service_message="You are not authorized to perform this operation.",
        http_status_code=403,
        expected_params={},
    )
    snapshot = clients.collector(services=("ec2",)).collect()
    clients.assert_all_consumed()
    assert snapshot["ec2_instances"] == [] and snapshot["security_groups"] == []
    assert coverage(snapshot, "ec2")["status"] == "missing"
    assert "UnauthorizedOperation" in coverage(snapshot, "ec2")["notes"][0]


def test_denied_route_tables_leave_routing_unknown_but_keep_instances(clients: Clients) -> None:
    stub_identity(clients)
    ec2 = clients["ec2"]
    ec2.add_response(
        "describe_instances",
        {
            "Reservations": [
                {
                    "ReservationId": "r-1",
                    "OwnerId": ACCOUNT,
                    "Instances": [
                        instance(
                            "i-0000000000000000a", subnet="subnet-public", public_ip="203.0.113.10"
                        )
                    ],
                }
            ]
        },
        {},
    )
    ec2.add_client_error(
        "describe_security_groups",
        service_error_code="UnauthorizedOperation",
        service_message="denied",
        http_status_code=403,
        expected_params={},
    )
    ec2.add_client_error(
        "describe_route_tables",
        service_error_code="UnauthorizedOperation",
        service_message="denied",
        http_status_code=403,
        expected_params={},
    )
    snapshot = clients.collector(services=("ec2",)).collect()
    clients.assert_all_consumed()
    (web,) = snapshot["ec2_instances"]
    assert web["internet_facing"] is None and web["security_groups"] == ["sg-web"]
    assert snapshot["security_groups"] == []
    ec2_coverage = coverage(snapshot, "ec2")
    assert ec2_coverage["status"] == "partial"
    assert any("DescribeSecurityGroups" in n for n in ec2_coverage["notes"])
    assert any("DescribeRouteTables" in n for n in ec2_coverage["notes"])


@pytest.mark.parametrize(
    ("subnet", "expected"),
    [("subnet-public", True), ("subnet-private", False), (None, False)],
)
def test_route_table_lookup_prefers_explicit_association(
    subnet: str | None, expected: bool
) -> None:
    from attackpath.aws.inventory import _subnet_routes_to_internet_gateway

    tables = route_tables()["RouteTables"]
    assert _subnet_routes_to_internet_gateway(tables, subnet, VPC) is expected
    assert _subnet_routes_to_internet_gateway(tables, "subnet-x", "vpc-other") is None
    assert _subnet_routes_to_internet_gateway([], "subnet-public", VPC) is None
