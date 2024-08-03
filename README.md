# Complete Setup Guide for a Secure MySQL Server on AWS RDS

#### 1. **Infrastructure Setup**

##### Create VPC and Subnets
Ensure that your database is in a private subnet, isolated from the public internet.

```bash
# Create a VPC
aws ec2 create-vpc --cidr-block 10.0.0.0/16 --region us-east-1
VPC_ID=$(aws ec2 describe-vpcs --filters Name=cidr-block,Values=10.0.0.0/16 --query 'Vpcs[0].VpcId' --output text)

# Create subnets
aws ec2 create-subnet --vpc-id $VPC_ID --cidr-block 10.0.1.0/24 --availability-zone us-east-1a
aws ec2 create-subnet --vpc-id $VPC_ID --cidr-block 10.0.2.0/24 --availability-zone us-east-1b
```

##### Create Security Groups
Use security groups to control inbound and outbound traffic to your database instance.

```bash
# Create a security group for MySQL
aws ec2 create-security-group --group-name MySQLSecurityGroup --description "Security group for MySQL" --vpc-id $VPC_ID
SG_ID=$(aws ec2 describe-security-groups --filters Name=group-name,Values=MySQLSecurityGroup --query 'SecurityGroups[0].GroupId' --output text)

# Allow inbound MySQL traffic from application servers only
aws ec2 authorize-security-group-ingress --group-id $SG_ID --protocol tcp --port 3306 --source-group sg-application

# Allow outbound traffic for backups, monitoring, etc.
aws ec2 authorize-security-group-egress --group-id $SG_ID --protocol tcp --port 3306 --cidr 10.0.0.0/16
```

#### 2. **Provision RDS Instance with Encryption and IAM Authentication**

```bash
# Create the RDS instance with encryption and IAM authentication
aws rds create-db-instance \
    --db-instance-identifier mydbinstance \
    --db-instance-class db.t3.micro \
    --engine mysql \
    --allocated-storage 20 \
    --master-username admin \
    --master-user-password mypassword \
    --vpc-security-group-ids $SG_ID \
    --db-subnet-group-name mydbsubnetgroup \
    --multi-az \
    --storage-encrypted \
    --backup-retention-period 7 \
    --publicly-accessible false \
    --enable-iam-database-authentication \
    --region us-east-1
```

#### 3. **Database Configuration**

##### Enable SSL for MySQL

**Modify `my.cnf` for SSL:**

```ini
[mysqld]
ssl-ca=/path/to/ca-cert.pem
ssl-cert=/path/to/server-cert.pem
ssl-key=/path/to/server-key.pem

[client]
ssl-ca=/path/to/ca-cert.pem
ssl-cert=/path/to/client-cert.pem
ssl-key=/path/to/client-key.pem
```

**Update RDS Parameter Group:**

```bash
aws rds create-db-parameter-group --db-parameter-group-name mydbparametergroup --db-parameter-group-family mysql8.0 --description "My DB parameter group"
aws rds modify-db-parameter-group --db-parameter-group-name mydbparametergroup --parameters "ParameterName=ssl_ca,ParameterValue=/path/to/rds-combined-ca-bundle.pem,ApplyMethod=immediate"
```

##### Enforce SSL/TLS Connections

```sql
-- Connect to the database and enforce SSL
mysql> CALL mysql.rds_set_configuration('require_ssl', 1);
```

#### 4. **Access Control and Authentication**

##### Create IAM Policies and Roles

**IAM Policy for RDS Access:**

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "rds-db:connect"
      ],
      "Resource": [
        "arn:aws:rds-db:us-east-1:123456789012:dbuser:mydbinstance/admin"
      ]
    }
  ]
}
```

**Attach IAM Role to EC2 Instances:**

```bash
# Create IAM role
aws iam create-role --role-name MyRDSRole --assume-role-policy-document file://trust-policy.json

# Attach policy to the role
aws iam put-role-policy --role-name MyRDSRole --policy-name MyRDSPolicy --policy-document file://policy.json

# Attach the role to an EC2 instance
aws ec2 associate-iam-instance-profile --instance-id i-1234567890abcdef0 --iam-instance-profile Name=MyRDSRole
```

#### 5. **Network and Application Security**

##### VPC and Network ACLs

**Create and Configure Network ACLs:**

```bash
# Create a Network ACL
aws ec2 create-network-acl --vpc-id $VPC_ID

# Add inbound rule
aws ec2 create-network-acl-entry --network-acl-id acl-12345678 --rule-number 100 --protocol tcp --port-range From=3306,To=3306 --egress --cidr-block 10.0.0.0/16 --rule-action allow

# Add outbound rule
aws ec2 create-network-acl-entry --network-acl-id acl-12345678 --rule-number 100 --protocol tcp --port-range From=3306,To=3306 --cidr-block 10.0.0.0/16 --rule-action allow
```

#### 6. **Monitoring and Auditing**

##### Enable CloudWatch Logs and Enhanced Monitoring

```bash
# Enable enhanced monitoring
aws rds modify-db-instance --db-instance-identifier mydbinstance --monitoring-role-arn arn:aws:iam::123456789012:role/emaccess --monitoring-interval 60

# Enable CloudWatch logs
aws rds modify-db-instance --db-instance-identifier mydbinstance --cloudwatch-logs-export-configuration 'ExportConfiguration={EnableLogTypes=["error","general","slowquery"]}'
```

##### Set Up CloudWatch Alarms

```bash
# Create a CloudWatch alarm for CPU utilization
aws cloudwatch put-metric-alarm --alarm-name HighCPUUtilization --metric-name CPUUtilization --namespace AWS/RDS --statistic Average --period 300 --threshold 80 --comparison-operator GreaterThanThreshold --dimensions Name=DBInstanceIdentifier,Value=mydbinstance --evaluation-periods 2 --alarm-actions arn:aws:sns:us-east-1:123456789012:MyTopic
```

#### 7. **Web Application Security**

##### Set Security Headers

In your web application, set security headers to enhance protection. Here's an example for an Express.js application:

```javascript
const helmet = require('helmet');
const express = require('express');
const app = express();

app.use(helmet());

app.get('/', (req, res) => {
  res.send('Hello, world!');
});

app.listen(3000);
```

**Headers to include:**
- **Content-Security-Policy (CSP)**: Prevents XSS and data injection attacks.
- **Strict-Transport-Security (HSTS)**: Enforces secure (HTTP over SSL/TLS) connections.
- **X-Content-Type-Options**: Prevents browsers from interpreting files as a different MIME type.
- **X-Frame-Options**: Prevents clickjacking.
- **X-XSS-Protection**: Enables the browser's built-in XSS filtering.

**Example CSP:**

```http
Content-Security-Policy: default-src 'self'; img-src 'self' https:; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline';
```

#### 8. **Advanced Security Measures**

##### Enable Data Masking

```sql
-- Example to mask sensitive data
SELECT 'XXXXX' AS masked_ssn FROM users WHERE ssn='123-45-6789';
```

##### Use Stored Procedures for Data Access

```sql
-- Example stored procedure
CREATE PROCEDURE GetUserData(IN user_id INT)
BEGIN
  SELECT name, email FROM users WHERE id = user_id;
END;
```

##### Use AWS KMS for Key Management

```bash
# Create a KMS key
aws kms create-key --description "RDS encryption key"

# Enable KMS encryption on RDS instance
aws rds modify-db-instance --db-instance-identifier mydbinstance --kms-key-id arn:aws:kms:us-east-1:123456789012:key/abcd1234-5678-90ab-cdef-1234567890ab
```

##### Transparent Data Encryption (TDE) for SQL Server

```sql
-- Enable TDE on SQL Server
USE master;
GO
CREATE DATABASE ENCRYPTION KEY
WITH ALGORITHM = AES_256
ENCRYPTION BY SERVER CERTIFICATE MyServerCert;
GO
ALTER DATABASE MyDatabase
SET ENCRYPTION ON;
GO
```

##### Use AWS PrivateLink

```bash
# Create a VPC endpoint for RDS
aws ec2 create-vpc-endpoint --vpc-id $VPC_ID --service-name com.amazonaws.us-east-1.rds --subnet-ids subnet-12345678 --security-group-ids $SG_ID
```

Sure, let's continue with the advanced security measures, regular security audits, patch management, and summary.

### Continued Advanced Security Measures

#### 9. **Network Security Enhancements**

##### Implement Network Firewalls

```bash
# Example firewall rule to block specific IP
iptables -A INPUT -s 203.0.113.0 -j DROP
```

#### 10. **Application Security Enhancements**

##### Implement Web Application Firewall (WAF)

```bash
# Create a WAF rule to block SQL injection
aws wafv2 create-web-acl --name MyWebACL --scope REGIONAL --default-action Block={} --rules '[
  {
    "Name": "SQLInjectionRule",
    "Priority": 1,
    "Statement": {
      "SqliMatchStatement": {
        "FieldToMatch": {
          "AllQueryArguments": {}
        },
        "TextTransformations": [
          {
            "Priority": 0,
            "Type": "URL_DECODE"
          }
        ]
      }
    },
    "Action": {
      "Block": {}
    },
    "VisibilityConfig": {
      "SampledRequestsEnabled": true,
      "CloudWatchMetricsEnabled": true,
      "MetricName": "SQLInjectionRule"
    }
  }
]' --region us-east-1
```

##### Use API Gateways

```bash
# Create an API Gateway
aws apigateway create-rest-api --name 'MyAPI'
```

#### 11. **Identity and Access Management (IAM) Enhancements**

##### Implement Role-Based Access Control (RBAC)

```sql
-- Create roles
CREATE ROLE read_only;
CREATE ROLE read_write;

-- Grant permissions
GRANT SELECT ON database.* TO read_only;
GRANT SELECT, INSERT, UPDATE, DELETE ON database.* TO read_write;

-- Assign roles to users
GRANT read_only TO 'username'@'hostname';
```

##### Enable Multi-Factor Authentication (MFA)

```bash
# Create MFA device
aws iam create-virtual-mfa-device --virtual-mfa-device-name MyMFADevice

# Associate MFA device with user
aws iam enable-mfa-device --user-name MyUser --serial-number arn:aws:iam::123456789012:mfa/MyMFADevice --authentication-code1 123456 --authentication-code2 789012
```

#### 12. **Intrusion Detection and Prevention**

##### Use AWS GuardDuty

```bash
# Enable GuardDuty
aws guardduty create-detector --enable
```

##### Implement Host-Based Intrusion Detection Systems (HIDS)

```bash
# Example using OSSEC for HIDS
sudo apt-get install ossec-hids
sudo /var/ossec/bin/ossec-control start
```

#### 13. **Regular Security Audits and Penetration Testing**

##### Schedule Regular Security Audits

```bash
# Example audit checklist
- Review IAM policies and roles.
- Check for open security group rules.
- Ensure encryption is enabled for all data at rest and in transit.
- Verify SSL/TLS configurations.
- Review CloudWatch logs and alarms.
- Conduct penetration testing.
```

#### 14. **Patch Management**

##### Automate Patch Management

```bash
# Create a patch baseline
aws ssm create-patch-baseline --name "MyPatchBaseline" --operating-system AMAZON_LINUX_2 --approval-rule-patch-filter-group "PatchRules=[{PatchFilterGroup={PatchFilters=[{Key=CLASSIFICATION,Values=[Security]},{Key=SEVERITY,Values=[Critical]}]},ApproveAfterDays=7}]"

# Apply the patch baseline
aws ssm create-patch-group --patch-group "MyPatchGroup" --baseline-id "pb-0123456789abcdef0"
```

#### 15. **Additional Considerations**

##### Database Backups and Recovery

- Regularly backup your RDS database using automated snapshots.
- Test recovery procedures to ensure data can be restored in case of a failure.

##### Data Masking

- Implement data masking techniques to protect sensitive data from unauthorized access.

##### Regular Updates

- Ensure that all components, including the database, operating system, and application, are regularly updated with security patches.

### Source Files and Configuration

#### `trust-policy.json`

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": {
        "Service": "ec2.amazonaws.com"
      },
      "Action": "sts:AssumeRole"
    }
  ]
}
```

#### `policy.json`

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "rds-db:connect"
      ],
      "Resource": [
        "arn:aws:rds-db:us-east-1:123456789012:dbuser:mydbinstance/admin"
      ]
    }
  ]
}
```

#### Example `my.cnf` for MySQL SSL

```ini
[mysqld]
ssl-ca=/path/to/ca-cert.pem
ssl-cert=/path/to/server-cert.pem
ssl-key=/path/to/server-key.pem

[client]
ssl-ca=/path/to/ca-cert.pem
ssl-cert=/path/to/client-cert.pem
ssl-key=/path/to/client-key.pem
```
