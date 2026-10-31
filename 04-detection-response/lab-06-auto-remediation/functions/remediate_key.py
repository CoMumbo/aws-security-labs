import json
import boto3
import os

iam = boto3.client("iam")

def lambda_handler(event, context):
    print(f"Received event: {json.dumps(event)}")
    
    # Extract the access key ID from the event detail
    detail = event.get("detail", {})
    access_key_id = detail.get("accessKeyId") or detail.get("accessKeyDetails", {}).get("accessKeyId")
    
    if not access_key_id:
        print("No access key ID found in event")
        return {"statusCode": 400, "body": "No access key ID"}
    
    print(f"Attempting to remediate access key: {access_key_id}")
    
    # Find which user owns this key
    users = iam.list_users()["Users"]
    for user in users:
        keys = iam.list_access_keys(UserName=user["UserName"])["AccessKeyMetadata"]
        for key in keys:
            if key["AccessKeyId"] == access_key_id:
                print(f"Found key on user {user['UserName']}, status: {key['Status']}")
                
                if key["Status"] == "Active":
                    iam.update_access_key(
                        UserName=user["UserName"],
                        AccessKeyId=access_key_id,
                        Status="Inactive"
                    )
                    print(f"DEACTIVATED key {access_key_id} on user {user['UserName']}")
                    return {
                        "statusCode": 200,
                        "body": json.dumps({
                            "action": "deactivated",
                            "user": user["UserName"],
                            "key": access_key_id
                        })
                    }
                else:
                    print(f"Key already inactive, no action needed")
                    return {"statusCode": 200, "body": "Key already inactive"}
    
    print(f"Access key {access_key_id} not found on any user")
    return {"statusCode": 404, "body": "Key not found"}
