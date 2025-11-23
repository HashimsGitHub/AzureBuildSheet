import streamlit as st
import pandas as pd
from datetime import datetime
import json
import base64

def create_bicep_template(form_data):
    """Generate Bicep template based on form inputs"""
    
    bicep_template = f"""
// Generated Bicep Template
// Created: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
// Description: {form_data.get('deployment_description', 'Azure infrastructure deployment')}

// Parameters
param location string = '{form_data['location']}'
param resourceGroupName string = '{form_data['resource_group_name']}'

// Resource Group
resource rg 'Microsoft.Resources/resourceGroups@2021-04-01' = {{
  name: resourceGroupName
  location: location
}}

// Virtual Network
resource vnet 'Microsoft.Network/virtualNetworks@2021-05-01' = {{
  name: '{form_data['vnet_name']}'
  location: rg.location
  dependsOn: [
    rg
  ]
  properties: {{
    addressSpace: {{
      addressPrefixes: [
        '{form_data['vnet_address_space']}'
      ]
    }}
    subnets: [
      {{
        name: '{form_data['subnet_name']}'
        properties: {{
          addressPrefix: '{form_data['subnet_address_prefix']}'
        }}
      }}
      {{
        name: 'AzureBastionSubnet'
        properties: {{
          addressPrefix: '{form_data.get('bastion_subnet_prefix', '10.0.2.0/24')}'
        }}
      }}
    ]
  }}
}}
"""

    # Add Storage Account if requested
    if form_data.get('create_storage_account', False):
        bicep_template += f"""
// Storage Account
resource storageAccount 'Microsoft.Storage/storageAccounts@2021-09-01' = {{
  name: '{form_data['storage_account_name']}'
  location: rg.location
  kind: 'StorageV2'
  sku: {{
    name: '{form_data['storage_sku']}'
  }}
  properties: {{
    supportsHttpsTrafficOnly: true
    minimumTlsVersion: 'TLS1_2'
    accessTier: '{(form_data.get("storage_access_tier", "Hot"))}'
  }}
  dependsOn: [
    rg
  ]
}}

// Storage Account Blob Container
resource blobContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2021-09-01' = {{
  name: '{form_data['storage_account_name']}/default/{form_data.get('blob_container_name', 'data')}'
  properties: {{
    publicAccess: 'None'
  }}
  dependsOn: [
    storageAccount
  ]
}}
"""

    # Add Virtual Machine if requested
    if form_data.get('create_vm', False):
        bicep_template += f"""
// Network Interface for VM
resource nic 'Microsoft.Network/networkInterfaces@2021-05-01' = {{
  name: '${{vm.name}}-nic'
  location: rg.location
  properties: {{
    ipConfigurations: [
      {{
        name: 'ipconfig1'
        properties: {{
          privateIPAllocationMethod: 'Dynamic'
          subnet: {{
            id: vnet.properties.subnets[0].id
          }}
        }}
      }}
    ]
  }}
  dependsOn: [
    vnet
  ]
}}

// Virtual Machine
resource vm 'Microsoft.Compute/virtualMachines@2021-11-01' = {{
  name: '{form_data['vm_name']}'
  location: rg.location
  properties: {{
    hardwareProfile: {{
      vmSize: '{form_data['vm_size']}'
    }}
    storageProfile: {{
      imageReference: {{
        publisher: '{form_data['vm_image_publisher']}'
        offer: '{form_data['vm_image_offer']}'
        sku: '{form_data['vm_image_sku']}'
        version: 'latest'
      }}
      osDisk: {{
        createOption: 'FromImage'
        diskSizeGB: {form_data['vm_disk_size']}
        managedDisk: {{
          storageAccountType: '{form_data['vm_disk_type']}'
        }}
      }}
    }}
    osProfile: {{
      computerName: '{form_data['vm_name']}'
      adminUsername: '{form_data['vm_admin_username']}'
      adminPassword: '{form_data['vm_admin_password']}'
    }}
    networkProfile: {{
      networkInterfaces: [
        {{
          id: nic.id
        }}
      ]
    }}
  }}
  dependsOn: [
    nic
  ]
}}
"""

    # Add App Service if requested
    if form_data.get('create_app_service', False):
        bicep_template += f"""
// App Service Plan
resource appServicePlan 'Microsoft.Web/serverfarms@2021-02-01' = {{
  name: '{form_data['app_service_plan_name']}'
  location: rg.location
  sku: {{
    name: '{form_data['app_service_plan_sku']}'
    tier: '{form_data['app_service_plan_tier']}'
  }}
  dependsOn: [
    rg
  ]
}}

// Web App
resource webApp 'Microsoft.Web/sites@2021-02-01' = {{
  name: '{form_data['web_app_name']}'
  location: rg.location
  identity: {{
    type: 'SystemAssigned'
  }}
  properties: {{
    serverFarmId: appServicePlan.id
    siteConfig: {{
      netFrameworkVersion: 'v6.0'
      ftpsState: 'FtpsOnly'
      minTlsVersion: '1.2'
    }}
    httpsOnly: true
  }}
  dependsOn: [
    appServicePlan
  ]
}}
"""

    # Add Container Registry if requested
    if form_data.get('create_container_registry', False):
        bicep_template += f"""
// Container Registry
resource containerRegistry 'Microsoft.ContainerRegistry/registries@2021-09-01' = {{
  name: '{form_data['container_registry_name']}'
  location: rg.location
  sku: {{
    name: '{form_data['container_registry_sku']}'
  }}
  properties: {{
    adminUserEnabled: {str(form_data.get('enable_admin_user', False)).lower()}
  }}
  dependsOn: [
    rg
  ]
}}
"""

    # Add Azure Kubernetes Service if requested
    if form_data.get('create_aks', False):
        bicep_template += f"""
// Azure Kubernetes Service
resource aks 'Microsoft.ContainerService/managedClusters@2021-07-01' = {{
  name: '{form_data['aks_cluster_name']}'
  location: rg.location
  identity: {{
    type: 'SystemAssigned'
  }}
  properties: {{
    kubernetesVersion: '{form_data['kubernetes_version']}'
    dnsPrefix: '{form_data['dns_prefix']}'
    agentPoolProfiles: [
      {{
        name: 'agentpool'
        count: {form_data['node_count']}
        vmSize: '{form_data['node_vm_size']}'
        osType: 'Linux'
        mode: 'System'
        osDiskSizeGB: {form_data['node_disk_size']}
      }}
    ]
    linuxProfile: {{
      adminUsername: '{form_data['aks_admin_username']}'
      ssh: {{
        publicKeys: [
          {{
            keyData: '{form_data['ssh_public_key']}'
          }}
        ]
      }}
    }}
    networkProfile: {{
      networkPlugin: 'kubenet'
      serviceCidr: '{form_data.get('service_cidr', '10.0.3.0/24')}'
      dnsServiceIP: '{form_data.get('dns_service_ip', '10.0.3.10')}'
    }}
  }}
  dependsOn: [
    rg
  ]
}}
"""

    # Add Databases if requested
    if form_data.get('create_sql_server', False):
        bicep_template += f"""
// SQL Server
resource sqlServer 'Microsoft.Sql/servers@2021-02-01-preview' = {{
  name: '{form_data['sql_server_name']}'
  location: rg.location
  properties: {{
    administratorLogin: '{form_data['sql_admin_username']}'
    administratorLoginPassword: '{form_data['sql_admin_password']}'
    minimalTlsVersion: '1.2'
    version: '12.0'
  }}
  dependsOn: [
    rg
  ]
}}

// SQL Database
resource sqlDatabase 'Microsoft.Sql/servers/databases@2021-02-01-preview' = {{
  name: '{form_data['sql_server_name']}/{form_data['sql_database_name']}'
  location: rg.location
  sku: {{
    name: '{form_data['sql_database_sku']}'
    tier: '{form_data['sql_database_tier']}'
  }}
  properties: {{
    collation: 'SQL_Latin1_General_CP1_CI_AS'
    maxSizeBytes: {form_data.get('sql_db_size', 268435456000)}
  }}
  dependsOn: [
    sqlServer
  ]
}}

// SQL Server Firewall Rule
resource firewallRule 'Microsoft.Sql/servers/firewallRules@2021-02-01-preview' = {{
  name: '{form_data['sql_server_name']}/AllowAzureServices'
  properties: {{
    startIpAddress: '0.0.0.0'
    endIpAddress: '0.0.0.0'
  }}
  dependsOn: [
    sqlServer
  ]
}}
"""

    # Add Cosmos DB if requested
    if form_data.get('create_cosmos_db', False):
        bicep_template += f"""
// Cosmos DB Account
resource cosmosDB 'Microsoft.DocumentDB/databaseAccounts@2021-10-15' = {{
  name: '{form_data['cosmos_db_account_name']}'
  location: rg.location
  kind: 'GlobalDocumentDB'
  properties: {{
    databaseAccountOfferType: 'Standard'
    locations: [
      {{
        locationName: rg.location
        failoverPriority: 0
      }}
    ]
    consistencyPolicy: {{
      defaultConsistencyLevel: '{form_data['cosmos_consistency_level']}'
    }}
    enableFreeTier: {str(form_data.get('cosmos_free_tier', True)).lower()}
  }}
  dependsOn: [
    rg
  ]
}}

// Cosmos DB Database
resource cosmosDatabase 'Microsoft.DocumentDB/databaseAccounts/sqlDatabases@2021-10-15' = {{
  name: '{form_data['cosmos_db_account_name']}/{form_data['cosmos_database_name']}'
  properties: {{
    resource: {{
      id: '{form_data['cosmos_database_name']}'
    }}
  }}
  dependsOn: [
    cosmosDB
  ]
}}

// Cosmos DB Container
resource cosmosContainer 'Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers@2021-10-15' = {{
  name: '{form_data['cosmos_db_account_name']}/{form_data['cosmos_database_name']}/{form_data['cosmos_container_name']}'
  properties: {{
    resource: {{
      id: '{form_data['cosmos_container_name']}'
      partitionKey: {{
        paths: [
          '{form_data.get('cosmos_partition_key', '/id')}'
        ]
        kind: 'Hash'
      }}
      indexingPolicy: {{
        automatic: true
        indexingMode: 'Consistent'
      }}
    }}
  }}
  dependsOn: [
    cosmosDatabase
  ]
}}
"""

    # Add Security Resources
    if form_data.get('create_key_vault', False):
        bicep_template += f"""
// Key Vault
resource keyVault 'Microsoft.KeyVault/vaults@2021-06-01-preview' = {{
  name: '{form_data['key_vault_name']}'
  location: rg.location
  properties: {{
    tenantId: subscription().tenantId
    sku: {{
      name: '{form_data['key_vault_sku']}'
      family: 'A'
    }}
    accessPolicies: [
      {{
        tenantId: subscription().tenantId
        objectId: '{form_data.get('key_vault_admin_object_id', '')}'
        permissions: {{
          keys: ['get', 'list', 'create', 'delete']
          secrets: ['get', 'list', 'set', 'delete']
          certificates: ['get', 'list', 'create', 'delete']
        }}
      }}
    ]
    enableSoftDelete: true
    enablePurgeProtection: {str(form_data.get('enable_purge_protection', True)).lower()}
  }}
  dependsOn: [
    rg
  ]
}}
"""

    # Add Bastion Host if requested
    if form_data.get('create_bastion', False):
        bicep_template += f"""
// Bastion Host
resource bastion 'Microsoft.Network/bastionHosts@2021-05-01' = {{
  name: '{form_data['bastion_name']}'
  location: rg.location
  properties: {{
    ipConfigurations: [
      {{
        name: 'bastionConfig'
        properties: {{
          subnet: {{
            id: vnet.properties.subnets[1].id
          }}
          publicIPAddress: {{
            id: bastionPublicIP.id
          }}
        }}
      }}
    ]
  }}
  dependsOn: [
    vnet
  ]
}}

// Bastion Public IP
resource bastionPublicIP 'Microsoft.Network/publicIPAddresses@2021-05-01' = {{
  name: '{form_data['bastion_name']}-pip'
  location: rg.location
  properties: {{
    publicIPAllocationMethod: 'Static'
    sku: {{
      name: 'Standard'
    }}
  }}
  dependsOn: [
    rg
  ]
}}
"""

    # Add Network Security Group if requested
    if form_data.get('create_nsg', False):
        bicep_template += f"""
// Network Security Group
resource nsg 'Microsoft.Network/networkSecurityGroups@2021-05-01' = {{
  name: '{form_data['nsg_name']}'
  location: rg.location
  properties: {{
    securityRules: [
      {{
        name: 'SSH'
        properties: {{
          description: 'Allow SSH'
          protocol: 'Tcp'
          sourcePortRange: '*'
          destinationPortRange: '22'
          sourceAddressPrefix: '{form_data.get('ssh_source_prefix', 'Internet')}'
          destinationAddressPrefix: '*'
          access: 'Allow'
          priority: 1000
          direction: 'Inbound'
        }}
      }},
      {{
        name: 'HTTP'
        properties: {{
          description: 'Allow HTTP'
          protocol: 'Tcp'
          sourcePortRange: '*'
          destinationPortRange: '80'
          sourceAddressPrefix: 'Internet'
          destinationAddressPrefix: '*'
          access: 'Allow'
          priority: 1010
          direction: 'Inbound'
        }}
      }},
      {{
        name: 'HTTPS'
        properties: {{
          description: 'Allow HTTPS'
          protocol: 'Tcp'
          sourcePortRange: '*'
          destinationPortRange: '443'
          sourceAddressPrefix: 'Internet'
          destinationAddressPrefix: '*'
          access: 'Allow'
          priority: 1020
          direction: 'Inbound'
        }}
      }}
    ]
  }}
  dependsOn: [
    rg
  ]
}}
"""

    return bicep_template

def create_excel_file(form_data):
    """Create Excel file with deployment details"""
    
    # Create DataFrame for resource summary
    summary_data = {
        'Resource Type': ['Resource Group', 'Virtual Network', 'Subnet'],
        'Resource Name': [
            form_data['resource_group_name'],
            form_data['vnet_name'],
            form_data['subnet_name']
        ],
        'Configuration': [
            f"Location: {form_data['location']}",
            f"Address Space: {form_data['vnet_address_space']}",
            f"Address Prefix: {form_data['subnet_address_prefix']}"
        ]
    }
    
    # Add additional resources if created
    resource_mappings = [
        ('create_storage_account', 'Storage Account', lambda: f"SKU: {form_data['storage_sku']}"),
        ('create_vm', 'Virtual Machine', lambda: f"Size: {form_data['vm_size']}, OS: {form_data['vm_image_offer']}"),
        ('create_app_service', 'App Service Plan', lambda: f"Tier: {form_data['app_service_plan_tier']}"),
        ('create_app_service', 'Web App', lambda: f"Framework: .NET 6.0"),
        ('create_container_registry', 'Container Registry', lambda: f"SKU: {form_data['container_registry_sku']}"),
        ('create_aks', 'AKS Cluster', lambda: f"Version: {form_data['kubernetes_version']}, Nodes: {form_data['node_count']}"),
        ('create_sql_server', 'SQL Server', lambda: f"Version: 12.0"),
        ('create_sql_server', 'SQL Database', lambda: f"Tier: {form_data['sql_database_tier']}"),
        ('create_cosmos_db', 'Cosmos DB', lambda: f"Consistency: {form_data['cosmos_consistency_level']}"),
        ('create_key_vault', 'Key Vault', lambda: f"SKU: {form_data['key_vault_sku']}"),
        ('create_bastion', 'Bastion Host', lambda: "Secure VM access"),
        ('create_nsg', 'Network Security Group', lambda: "Security rules configured")
    ]
    
    for condition, resource_type, config_func in resource_mappings:
        if form_data.get(condition, False):
            summary_data['Resource Type'].append(resource_type)
            summary_data['Resource Name'].append(form_data.get(f"{resource_type.lower().replace(' ', '_')}_name", resource_type))
            summary_data['Configuration'].append(config_func())
    
    df_summary = pd.DataFrame(summary_data)
    
    # Create DataFrame for parameters
    params_data = {
        'Parameter': list(form_data.keys()),
        'Value': [str(v) for v in form_data.values()]
    }
    df_params = pd.DataFrame(params_data)
    
    return df_summary, df_params

def get_table_download_link(df, filename, sheet_name):
    """Generate a download link for Excel file"""
    output = pd.ExcelWriter(filename, engine='openpyxl')
    df.to_excel(output, sheet_name=sheet_name, index=False)
    output.close()
    
    with open(filename, 'rb') as f:
        data = f.read()
    b64 = base64.b64encode(data).decode()
    href = f'<a href="data:application/vnd.openxmlformats-officedocument.spreadsheetml.sheet;base64,{b64}" download="{filename}">Download {filename}</a>'
    return href

def get_bicep_download_link(content, filename):
    """Generate a download link for Bicep file"""
    b64 = base64.b64encode(content.encode()).decode()
    href = f'<a href="data:text/plain;base64,{b64}" download="{filename}">Download {filename}</a>'
    return href

def main():
    st.set_page_config(page_title="Azure Bicep Generator", page_icon="🚀", layout="wide")
    
    st.title("🚀 Azure Bicep Template Generator")
    st.markdown("Fill out the form below to generate Bicep templates and Excel deployment files for Azure resources.")
    
    # Initialize session state for form data
    if 'form_data' not in st.session_state:
        st.session_state.form_data = {}
    
    with st.form("azure_deployment_form"):
        st.header("📋 Basic Configuration")
        
        col1, col2 = st.columns(2)
        
        with col1:
            resource_group_name = st.text_input("Resource Group Name", value="rg-myproject-dev")
            location = st.selectbox("Location", [
                "australiaeast","australiasoutheast"
            ])
            vnet_name = st.text_input("Virtual Network Name", value="vnet-core")
            vnet_address_space = st.text_input("VNet Address Space", value="10.0.0.0/16")
        
        with col2:
            subnet_name = st.text_input("Subnet Name", value="snet-default")
            subnet_address_prefix = st.text_input("Subnet Address Prefix", value="10.0.1.0/24")
            deployment_description = st.text_area("Deployment Description", value="Azure infrastructure deployment with security and containers")
        
        st.header("🛡️ Security Resources")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            create_key_vault = st.checkbox("Create Key Vault")
            create_bastion = st.checkbox("Create Bastion Host")
            create_nsg = st.checkbox("Create Network Security Group")
        
        with col2:
            if create_key_vault:
                key_vault_name = st.text_input("Key Vault Name", value="kv-myproject-dev")
                key_vault_sku = st.selectbox("Key Vault SKU", ["standard", "premium"])
                key_vault_admin_object_id = st.text_input("Admin Object ID", placeholder="Enter Azure AD Object ID")
                enable_purge_protection = st.checkbox("Enable Purge Protection", value=True)
            
            if create_bastion:
                bastion_name = st.text_input("Bastion Name", value="bastion-dev")
                bastion_subnet_prefix = st.text_input("Bastion Subnet Prefix", value="10.0.2.0/24")
        
        with col3:
            if create_nsg:
                nsg_name = st.text_input("NSG Name", value="nsg-default")
                ssh_source_prefix = st.text_input("SSH Source Prefix", value="Internet")
        
        st.header("🐳 Container Resources")
        
        col1, col2 = st.columns(2)
        
        with col1:
            create_container_registry = st.checkbox("Create Container Registry")
            create_aks = st.checkbox("Create Azure Kubernetes Service (AKS)")
        
        with col2:
            if create_container_registry:
                container_registry_name = st.text_input("Container Registry Name", value="crmyprojectdev")
                container_registry_sku = st.selectbox("ACR SKU", ["Basic", "Standard", "Premium"])
                enable_admin_user = st.checkbox("Enable Admin User")
            
            if create_aks:
                aks_cluster_name = st.text_input("AKS Cluster Name", value="aks-myproject-dev")
                kubernetes_version = st.selectbox("Kubernetes Version", ["1.27", "1.26", "1.25"])
                dns_prefix = st.text_input("DNS Prefix", value="myproject-dev")
                node_count = st.slider("Node Count", 1, 10, 3)
                node_vm_size = st.selectbox("Node VM Size", ["Standard_B2s", "Standard_D2s_v3", "Standard_D4s_v3"])
                node_disk_size = st.slider("Node Disk Size (GB)", 30, 1024, 128)
                aks_admin_username = st.text_input("AKS Admin Username", value="azureuser")
                ssh_public_key = st.text_area("SSH Public Key", placeholder="ssh-rsa AAAAB3NzaC1yc2E...")
                service_cidr = st.text_input("Service CIDR", value="10.0.3.0/24")
                dns_service_ip = st.text_input("DNS Service IP", value="10.0.3.10")
        
        st.header("🗄️ Database Resources")
        
        col1, col2 = st.columns(2)
        
        with col1:
            create_sql_server = st.checkbox("Create SQL Server & Database")
            if create_sql_server:
                sql_server_name = st.text_input("SQL Server Name", value="sql-myproject-dev")
                sql_database_name = st.text_input("SQL Database Name", value="sqldb-myproject")
                sql_admin_username = st.text_input("SQL Admin Username", value="sqladmin")
                sql_admin_password = st.text_input("SQL Admin Password", type="password", value="Password123!")
                sql_database_sku = st.selectbox("SQL Database SKU", ["Basic", "S0", "S1", "S2", "S3"])
                sql_database_tier = st.selectbox("SQL Database Tier", ["Basic", "Standard", "Premium", "GeneralPurpose", "BusinessCritical"])
                sql_db_size = st.number_input("SQL DB Size (Bytes)", value=268435456000)
        
        with col2:
            create_cosmos_db = st.checkbox("Create Cosmos DB")
            if create_cosmos_db:
                cosmos_db_account_name = st.text_input("Cosmos DB Account Name", value="cosmos-myproject-dev")
                cosmos_database_name = st.text_input("Cosmos Database Name", value="cosmosdb-myproject")
                cosmos_container_name = st.text_input("Cosmos Container Name", value="items")
                cosmos_consistency_level = st.selectbox("Consistency Level", ["Session", "Eventual", "ConsistentPrefix", "BoundedStaleness", "Strong"])
                cosmos_partition_key = st.text_input("Partition Key Path", value="/id")
                cosmos_free_tier = st.checkbox("Enable Free Tier", value=True)
        
        st.header("⚙️ Optional Compute Resources")
        
        col1, col2, col3 = st.columns(3)
        
        with col1:
            create_storage_account = st.checkbox("Create Storage Account")
            create_vm = st.checkbox("Create Virtual Machine")
            create_app_service = st.checkbox("Create App Service")
        
        with col2:
            if create_storage_account:
                storage_account_name = st.text_input("Storage Account Name", value="stmyprojectdev")
                storage_sku = st.selectbox("Storage SKU", ["Standard_LRS", "Standard_GRS", "Standard_RAGRS", "Premium_LRS"])
                storage_access_tier = st.selectbox("Storage Access Tier", ["Hot", "Cool"])
                blob_container_name = st.text_input("Blob Container Name", value="data")
            
            if create_vm:
                vm_name = st.text_input("VM Name", value="vm-dev-01")
                vm_size = st.selectbox("VM Size", ["Standard_B1s", "Standard_B2s", "Standard_D2s_v3", "Standard_D4s_v3"])
                vm_image_publisher = st.text_input("VM Image Publisher", value="MicrosoftWindowsServer")
                vm_image_offer = st.text_input("VM Image Offer", value="WindowsServer")
                vm_image_sku = st.text_input("VM Image SKU", value="2019-Datacenter")
                vm_disk_size = st.number_input("VM Disk Size (GB)", min_value=32, max_value=4095, value=128)
                vm_disk_type = st.selectbox("VM Disk Type", ["Standard_LRS", "StandardSSD_LRS", "Premium_LRS"])
                vm_admin_username = st.text_input("VM Admin Username", value="azureuser")
                vm_admin_password = st.text_input("VM Admin Password", type="password", value="Password123!")
        
        with col3:
            if create_app_service:
                app_service_plan_name = st.text_input("App Service Plan Name", value="asp-myproject-dev")
                app_service_plan_tier = st.selectbox("App Service Plan Tier", ["Basic", "Standard", "Premium", "Free", "Shared"])
                app_service_plan_sku = st.selectbox("App Service Plan SKU", ["B1", "B2", "B3", "S1", "S2", "S3", "P1", "P2", "P3"])
                web_app_name = st.text_input("Web App Name", value="app-myproject-dev")
        
        submitted = st.form_submit_button("🚀 Generate Deployment Files")
        
        if submitted:
            # Collect all form data
            form_data = {
                'resource_group_name': resource_group_name,
                'location': location,
                'vnet_name': vnet_name,
                'vnet_address_space': vnet_address_space,
                'subnet_name': subnet_name,
                'subnet_address_prefix': subnet_address_prefix,
                'deployment_description': deployment_description,
                'create_storage_account': create_storage_account,
                'create_vm': create_vm,
                'create_app_service': create_app_service,
                'create_container_registry': create_container_registry,
                'create_aks': create_aks,
                'create_sql_server': create_sql_server,
                'create_cosmos_db': create_cosmos_db,
                'create_key_vault': create_key_vault,
                'create_bastion': create_bastion,
                'create_nsg': create_nsg,
            }
            
            # Add conditional data
            conditional_fields = {
                'create_storage_account': ['storage_account_name', 'storage_sku', 'storage_access_tier', 'blob_container_name'],
                'create_vm': ['vm_name', 'vm_size', 'vm_image_publisher', 'vm_image_offer', 'vm_image_sku', 
                            'vm_disk_size', 'vm_disk_type', 'vm_admin_username', 'vm_admin_password'],
                'create_app_service': ['app_service_plan_name', 'app_service_plan_tier', 'app_service_plan_sku', 'web_app_name'],
                'create_container_registry': ['container_registry_name', 'container_registry_sku', 'enable_admin_user'],
                'create_aks': ['aks_cluster_name', 'kubernetes_version', 'dns_prefix', 'node_count', 'node_vm_size', 
                             'node_disk_size', 'aks_admin_username', 'ssh_public_key', 'service_cidr', 'dns_service_ip'],
                'create_sql_server': ['sql_server_name', 'sql_database_name', 'sql_admin_username', 'sql_admin_password',
                                    'sql_database_sku', 'sql_database_tier', 'sql_db_size'],
                'create_cosmos_db': ['cosmos_db_account_name', 'cosmos_database_name', 'cosmos_container_name',
                                   'cosmos_consistency_level', 'cosmos_partition_key', 'cosmos_free_tier'],
                'create_key_vault': ['key_vault_name', 'key_vault_sku', 'key_vault_admin_object_id', 'enable_purge_protection'],
                'create_bastion': ['bastion_name', 'bastion_subnet_prefix'],
                'create_nsg': ['nsg_name', 'ssh_source_prefix']
            }
            
            for condition, fields in conditional_fields.items():
                if form_data.get(condition, False):
                    for field in fields:
                        if field in locals():
                            form_data[field] = locals()[field]
            
            st.session_state.form_data = form_data
    
    # Generate and display files if form is submitted
    if st.session_state.form_data:
        st.header("📄 Generated Files")
        
        # Generate Bicep template
        bicep_content = create_bicep_template(st.session_state.form_data)
        
        # Generate Excel files
        df_summary, df_params = create_excel_file(st.session_state.form_data)
        
        # Display previews
        col1, col2 = st.columns(2)
        
        with col1:
            st.subheader("Bicep Template Preview")
            st.code(bicep_content, language='bicep')
        
        with col2:
            st.subheader("Deployment Summary Preview")
            st.dataframe(df_summary)
        
        # Download links
        st.subheader("📥 Download Files")
        
        # Bicep file download
        bicep_filename = f"azure-deployment-{datetime.now().strftime('%Y%m%d-%H%M%S')}.bicep"
        st.markdown(get_bicep_download_link(bicep_content, bicep_filename), unsafe_allow_html=True)
        
        # Excel file download
        excel_filename = f"azure-deployment-summary-{datetime.now().strftime('%Y%m%d-%H%M%S')}.xlsx"
        
        # Create Excel file with multiple sheets
        with pd.ExcelWriter(excel_filename, engine='openpyxl') as writer:
            df_summary.to_excel(writer, sheet_name='Resource Summary', index=False)
            df_params.to_excel(writer, sheet_name='Parameters', index=False)
        
        with open(excel_filename, 'rb') as f:
            excel_data = f.read()
        
        b64_excel = base64.b64encode(excel_data).decode()
        excel_href = f'<a href="data:application/vnd.openxmlformats-officedocument.spreadsheetml.sheet;base64,{b64_excel}" download="{excel_filename}">Download {excel_filename}</a>'
        st.markdown(excel_href, unsafe_allow_html=True)
        
        # Security Recommendations
        st.header("🛡️ Security Recommendations")
        
        security_tips = []
        if st.session_state.form_data.get('create_key_vault'):
            security_tips.append("✅ **Key Vault**: Store secrets, keys, and certificates securely")
        if st.session_state.form_data.get('create_nsg'):
            security_tips.append("✅ **NSG**: Network security rules configured for SSH, HTTP, HTTPS")
        if st.session_state.form_data.get('create_bastion'):
            security_tips.append("✅ **Bastion**: Secure RDP/SSH access without public IPs")
        
        if not security_tips:
            security_tips.append("⚠️ Consider adding security resources like Key Vault, NSG, or Bastion Host")
        
        for tip in security_tips:
            st.markdown(tip)
        
        # Deployment instructions
        st.header("🚀 Deployment Instructions")
        st.markdown("""
        1. **Download both files** using the links above
        2. **Review the Bicep template** and adjust parameters as needed
        3. **Deploy using Azure CLI:**
           ```bash
           az deployment group create \\
             --resource-group YOUR_RG_NAME \\
             --template-file azure-deployment.bicep
           ```
        4. **Or deploy using PowerShell:**
           ```powershell
           New-AzResourceGroupDeployment `
             -ResourceGroupName "YOUR_RG_NAME" `
             -TemplateFile "azure-deployment.bicep"
           ```
        5. **For AKS deployment**, after cluster creation:
           ```bash
           az aks get-credentials --resource-group YOUR_RG_NAME --name AKS_CLUSTER_NAME
           ```
        """)

if __name__ == "__main__":
    main()