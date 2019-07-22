#!/bin/bash

# My Aliases
function k() {
    /usr/local/bin/kubectl "$@"
}

function kctx() {
    /usr/local/bin/kubectl config use-context "$@"
}

## Only works on WSL
 function chrome(){
     /c/Program\ Files\ \(x86\)/Google/Chrome/Application/chrome.exe "$@"
}

# Variables
PREFIX="secdemo"
RG="${PREFIX}-rg"
LOC="westus2"
AKSNAME="${PREFIX}"
VNET_NAME="${PREFIX}vnet"
AKSSUBNET_NAME="${PREFIX}akssubnet"
SVCSUBNET_NAME="${PREFIX}svcsubnet"
APPGWSUBNET_NAME="${PREFIX}appgwsubnet"
FWSUBNET_NAME="AzureFirewallSubnet"
IDENTITY_NAME="${PREFIX}identity"
FWNAME="${PREFIX}fw"
FWPUBLICIP_NAME="${PREFIX}fwpublicip"
FWIPCONFIG_NAME="${PREFIX}fwconfig"
FWROUTE_TABLE_NAME="${PREFIX}fwrt"
FWROUTE_NAME="${PREFIX}fwrn"
AGNAME="${PREFIX}ag"
AGPUBLICIP_NAME="${PREFIX}agpublicip"
STORAGE_NAME="${PREFIX}${DATE}storage"
FILES_NAME="fruit"
AZURE_ACCOUNT_NAME="JPalma-Internal"
K8S_VERSION=1.13.5
VM_SIZE=Standard_D2s_v3
WINDOWS_PASSWORD='Pa$$w0rd2019!'
WINDOWS_USER="jpalma"
PLUGIN=azure
SUBID=$(az account show -s $AZURE_ACCOUNT_NAME -o tsv --query 'id')

usage()
{
    echo "usage: aks-test-setup.sh [[[-p Network_Plugin ] [-s NODE_VM_SIZE]] | [-h]]"
}


while [ "$1" != "" ]; do
  case $1 in
  -p | --plugin )         
    shift
    PLUGIN=$1
    ;;
  -s | --node-vm-size )
    shift   
    VM_SIZE=$1
    ;;
  -h | --help )
    usage
    exit
    ;;
  * )
    usage
    exit 1
  esac
  shift
done

# Setup right subscription
az account set -s $AZURE_ACCOUNT_NAME

# pre-clean up
az group delete -y -n $RG &> /dev/null
# az aks delete -y -n $AKSNAME -g $RG &> /dev/null 
az ad sp delete --id "http://${PREFIX}sp" &> /dev/null


# Create Resource Group if not exists
az group create --name $RG --location $LOC 2> /dev/null

# Create Virtual Network & Subnets for AKS, k8s Services, ACI, Firewall and WAF
az network vnet create \
    --resource-group $RG \
    --name $VNET_NAME \
    --address-prefixes 10.42.0.0/16 \
    --subnet-name $AKSSUBNET_NAME \
    --subnet-prefix 10.42.1.0/24
az network vnet subnet create \
    --resource-group $RG \
    --vnet-name $VNET_NAME \
    --name $SVCSUBNET_NAME \
    --address-prefix 10.42.2.0/24    
az network vnet subnet create \
    --resource-group $RG \
    --vnet-name $VNET_NAME \
    --name $APPGWSUBNET_NAME \
    --address-prefix 10.42.3.0/24
az network vnet subnet create \
    --resource-group $RG \
    --vnet-name $VNET_NAME \
    --name $FWSUBNET_NAME \
    --address-prefix 10.42.4.0/24

# Automatically print the SP values into $APPID and $PASSWORD, trust me
eval "$(az ad sp create-for-rbac -n ${PREFIX}sp --skip-assignment | jq -r '. | to_entries | .[] | .key + "=\"" + .value + "\""' | sed -r 's/^(.*=)/\U\1/')"
echo $APPID
echo $PASSWORD


# Get $VNETID & $SUBNETID
VNETID=$(az network vnet show -g $RG --name $VNET_NAME --query id -o tsv)
SUBNETID=$(az network vnet subnet show -g $RG --vnet-name $VNET_NAME --name $AKSSUBNET_NAME --query id -o tsv)



# Create Public IP
az network public-ip create -g $RG -n $FWPUBLICIP_NAME -l $LOC --sku "Standard"
# Create Firewall
az extension add --name azure-firewall
az network firewall create -g $RG -n $FWNAME -l $LOC
# Configure Firewall IP Config
# This command will take a few mins.
az network firewall ip-config create -g $RG -f $FWNAME -n $FWIPCONFIG_NAME --public-ip-address $FWPUBLICIP_NAME --vnet-name $VNET_NAME
# Capture Firewall IP Address for Later Use
FWPUBLIC_IP=$(az network public-ip show -g $RG -n $FWPUBLICIP_NAME --query "ipAddress" -o tsv)
FWPRIVATE_IP=$(az network firewall show -g $RG -n $FWNAME --query "ipConfigurations[0].privateIpAddress" -o tsv)
# Validate Firewall IP Address Values
echo $FWPUBLIC_IP
echo $FWPRIVATE_IP
# Create UDR & Routing Table
az network route-table create -g $RG --name $FWROUTE_TABLE_NAME
az network route-table route create -g $RG --name $FWROUTE_NAME --route-table-name $FWROUTE_TABLE_NAME --address-prefix 0.0.0.0/0 --next-hop-type VirtualAppliance --next-hop-ip-address $FWPRIVATE_IP
# Add Network FW Rules
# TCP - * - * - 22
# Destination IP Addresses (US West 2 DC): 13.0.0.0/8 20.0.0.0/8 23.0.0.0/8 40.0.0.0/8 51.0.0.0/8 52.0.0.0/8 65.0.0.0/8 70.0.0.0/8 104.0.0.0/8 131.0.0.0/8 157.0.0.0/8 168.0.0.0/24 191.0.0.0/8 199.0.0.0/8 207.0.0.0/8 209.0.0.0/8

az network firewall network-rule create -g $RG -f $FWNAME --collection-name 'aksfwnr' -n 'netrules' --protocols 'TCP' --source-addresses '*' --destination-addresses '13.0.0.0/8' '20.0.0.0/8' '23.0.0.0/8' '40.0.0.0/8' '51.0.0.0/8' '52.0.0.0/8' '65.0.0.0/8' '70.0.0.0/8' '104.0.0.0/8' '131.0.0.0/8' '157.0.0.0/8' '168.0.0.0/24' '191.0.0.0/8' '199.0.0.0/8' '207.0.0.0/8' '209.0.0.0/8' --destination-ports 9000 22 443 53 445 --action allow --priority 100
# Add Application FW Rules
az network firewall application-rule create -g $RG -f $FWNAME --collection-name 'aksfwar' -n 'fqdn' --source-addresses '*' --protocols 'http=80' 'https=443' --target-fqdns 'jpalma.azurecr.io' '*.azmk8s.io' 'aksrepos.azurecr.io' '*blob.core.windows.net' '*mcr.microsoft.com' '*.cdn.mscr.io' 'login.microsoftonline.com' 'management.azure.com' '*ubuntu.com' --action allow --priority 100
# Associate AKS Subnet to FW
az network vnet subnet update -g $RG --vnet-name $VNET_NAME --name $AKSSUBNET_NAME --route-table $FWROUTE_TABLE_NAME

# Assign SP Permission to VNET
az role assignment create --assignee $APPID --scope $VNETID --role Contributor
ACR_ID=$(az acr show --name jpalma --resource-group acrjpalma --query "id" --output tsv)
az role assignment create --assignee $APPID --role acrpull --scope $ACR_ID 

# Create AKS
az aks create -g $RG -n $AKSNAME -l $LOC \
  --node-count 2 -k $K8S_VERSION -a monitoring\
  --network-plugin $PLUGIN \
  --network-policy azure \
  --windows-admin-password $WINDOWS_PASSWORD \
  --windows-admin-username $WINDOWS_USER \
  --service-cidr 10.41.0.0/16 \
  --dns-service-ip 10.41.0.10 \
  --docker-bridge-address 172.17.0.1/16 \
  --vnet-subnet-id $SUBNETID \
  --service-principal $APPID \
  --client-secret $PASSWORD \
  --enable-vmss


# Get AKS Credentials so kubectl works
az aks get-credentials -g $RG -n $AKSNAME --admin --overwrite-existing

# Get Nodes
k get nodes -o wide

# Create Azure App Gateway v2 with WAF and autoscale.
# Create Public IP First.
az network public-ip create -g $RG -n $AGPUBLICIP_NAME -l $LOC --sku "Standard"
# Create App Gateway using WAF_v2 SKU.
az network application-gateway create \
  --name $AGNAME \
  --resource-group $RG \
  --location $LOC \
  --min-capacity 2 \
  --frontend-port 80 \
  --http-settings-cookie-based-affinity Disabled \
  --http-settings-port 80 \
  --http-settings-protocol Http \
  --routing-rule-type Basic \
  --sku WAF_v2 \
  --private-ip-address 10.42.3.12 \
  --public-ip-address $AGPUBLICIP_NAME \
  --subnet $APPGWSUBNET_NAME \
  --vnet-name $VNET_NAME

# Deploy Azure AD Pod Identity
k apply -f https://raw.githubusercontent.com/Azure/aad-pod-identity/master/deploy/infra/deployment-rbac.yaml


# Create User Identity
IDENTITY=$(az identity create -g "MC_${RG}_${AKSNAME}_${LOC}" -n $IDENTITY_NAME)
echo $IDENTITY
ASSIGNEEID=$(echo $IDENTITY | jq .clientId | tr -d '"')
echo $ASSIGNEEID
sleep 50
# Assign Reader Role
ROLEREADER=$(az role assignment create --role Reader --assignee ${ASSIGNEEID} --scope "/subscriptions/${SUBID}/resourcegroups/MC_${RG}_${AKSNAME}_${LOC}")
echo $ROLEREADER

# Providing required permissions for MIC Using AKS SP
SCOPEID=$(echo $IDENTITY | jq .id | tr -d '"')
echo $SCOPEID
ROLEMIC=$(az role assignment create --role "Managed Identity Operator" --assignee $APPID --scope $SCOPEID)
echo $ROLEMIC

# Install User Azure AD Identity and update ResourceID,  ClientID and name in aadpodidentity.yaml with output of $IDENTITY
sed -i aadpodidentity.yaml -e "s/\(^.*ClientID: \).*/\1${ASSIGNEEID}/gI"
sed -i aadpodidentity.yaml -e 's@\(^.*ResourceID: \).*@\1'"${SCOPEID}"'@gI'
sed -i aadpodidentity.yaml -e "s/\(^.*name: \).*/\1${IDENTITY_NAME}/gI"

k apply -f aadpodidentity.yaml


# Install Pod to Identity Binding on k8s cluster and update name, AzureIdentity and Selector on aadpodidentitybinding.yaml with output of $IDENTITY
sed -i aadpodidentitybinding.yaml -e "s/\(^.*name: \).*/\1${PREFIX}-identity-binding/gI"
sed -i aadpodidentitybinding.yaml -e "s/\(^.*AzureIdentity: \).*/\1${IDENTITY_NAME}/gI"
sed -i aadpodidentitybinding.yaml -e "s/\(^.*Selector: \).*/\1${PREFIX}aadbindingselector/gI"

k apply -f aadpodidentitybinding.yaml

# Check out Sample Deployment Using AAD Pod Identity to ensure everything is working.
# Note: Update --subscriptionid --clientid and --resourcegroup in aadpodidentity-deployment.yaml accordingly.
sed -i aadpodidentity-deployment.yaml -e "s/\(^.*aadpodidbinding: \).*/\1${PREFIX}aadbindingselector/gI"
sed -i aadpodidentity-deployment.yaml -e "s/\(^.*subscriptionid=\).*/\1${SUBID}\"/gI"
sed -i aadpodidentity-deployment.yaml -e "s/\(^.*clientid=\).*/\1${ASSIGNEEID}\"/gI"
sed -i aadpodidentity-deployment.yaml -e "s/\(^.*resourcegroup=\).*/\1MC_${RG}_${AKSNAME}_${LOC}\"/gI"

k apply -f aadpodidentity-deployment.yaml

# Take note of the aadpodidentitybinding label as this determines which binding is used. 
k get po --show-labels -o wide
k logs $(kubectl get pod -l "app=demo" -o jsonpath='{.items[0].metadata.name}')
# k exec $(kubectl get pod -l "app=demo" -o jsonpath='{.items[0].metadata.name}') -- /bin/bash -c env
k delete -f aadpodidentity-deployment.yaml

# Setup App Gateway Ingress
# Get helm
curl -LO https://git.io/get_helm.sh
chmod 700 get_helm.sh
./get_helm.sh

# Setup Helm First
kubectl create serviceaccount --namespace kube-system tiller-sa
kubectl create clusterrolebinding tiller-cluster-rule --clusterrole=cluster-admin --serviceaccount=kube-system:tiller-sa
helm init --tiller-namespace kube-system --service-account tiller-sa
sleep 30
helm repo add application-gateway-kubernetes-ingress https://raw.githubusercontent.com/Azure/application-gateway-kubernetes-ingress/master/helm
helm repo update

# Install and Setup Ingress
# Grant AAD Identity Access to App Gateway

APPGATEWAYSCOPEID=$(az network application-gateway show -g $RG -n $AGNAME | jq .id | tr -d '"')
echo $APPGATEWAYSCOPEID
ROLEAGWCONTRIB=$(az role assignment create --role Contributor --assignee $ASSIGNEEID --scope $APPGATEWAYSCOPEID)
ROLEAGWREADER=$(az role assignment create --role Reader --assignee $ASSIGNEEID --scope "/subscriptions/${SUBID}/resourcegroups/${RG}")
ROLEAGWREADER2=$(az role assignment create --role Reader --assignee $ASSIGNEEID --scope $APPGATEWAYSCOPEID)
echo $ROLEAGWCONTRIB
echo $ROLEAGWREADER
echo $ROLEAGWREADER2

# Note: Update subscriptionId, resourceGroup, name, identityResourceID, identityClientID and apiServerAddress
# in agw-helm-config.yaml file with the following.


sed -i agw-helm-config.yaml -e "s/\(^.*subscriptionId: \).*/\1${SUBID}/gI"
sed -i agw-helm-config.yaml -e "s/\(^.*resourceGroup: \).*/\1${RG}/gI"
sed -i agw-helm-config.yaml -e "s/\(^.*name: \).*/\1${AGNAME}/gI"
sed -i agw-helm-config.yaml -e 's@\(^.*identityResourceID: \).*@\1'"${SCOPEID}"'@gI'
sed -i agw-helm-config.yaml -e "s/\(^.*identityClientID: \).*/\1${ASSIGNEEID}/gI"

APISERVER=$(az aks show -n $AKSNAME -g $RG --query 'fqdn' -o tsv)
sed -i agw-helm-config.yaml -e "s/\(^.*apiServerAddress: \).*/\1${APISERVER}/gI"

helm install --name $AGNAME -f agw-helm-config.yaml application-gateway-kubernetes-ingress/ingress-azure

# Check created resources
k get po,svc,ingress,deploy,secrets
helm list

## Deploy Workload
# Add Web Front-End

sed -i build19-web.yaml -e "s/\(^.*azure-load-balancer-internal-subnet: \).*/\1\"${SVCSUBNET_NAME}\"/gI"
k apply -f build19-web.yaml
k apply -f build19-ingress-web.yaml

# Add Worker Back-End
az storage account create -n $STORAGE_NAME -g $RG -l $LOC
STORAGE_KEY=$(az storage account keys list -n $STORAGE_NAME -g $RG --query [0].'value' -o tsv)

az storage share create -n $FILES_NAME --account-key $STORAGE_KEY --account-name $STORAGE_NAME
az storage file upload-batch --destination $FILES_NAME --source ~/workbench/readydemos/WinterReady2019/security/fruit/ --account-name $STORAGE_NAME --account-key $STORAGE_KEY

k create secret generic fruit-secret --from-literal=azurestorageaccountname=$STORAGE_NAME --from-literal=azurestorageaccountkey=$STORAGE_KEY

k apply -f build19-worker.yaml

k get po,svc,ingress,deploy,secrets

#Check workload
az network public-ip show -g $RG -n $AGPUBLICIP_NAME --query "ipAddress" -o tsv

# Browser or curl





