#!/bin/sh

# Create a self signed key pair root CA certificate.

function create_self_signing_cert_authority
{
ldname=$1
lksname=$2
lkalias=$3
lkeypass=$4
lkspass=$5

echo "Creating Root CA certificate... \n"

$keytool -genkeypair -v \
  -alias $lkalias \
  -dname $ldname \
  -keystore $lksname \
  -keypass $lkeypass \
  -storepass $lkspass \
  -keyalg RSA \
  -keysize 4096 \
  -ext KeyUsage:critical="keyCertSign" \
  -ext BasicConstraints:critical="ca:true" \
  -validity 9999
}

# Export the testCA public certificate as testca.crt so that it can be used in trust stores.
function export_cert 
{
lksname=$1
lkalias=$2
lkeypass=$3
lkspass=$4
lcertname=$5

echo "Exporting certificate to file to be named $lcertname ... \n"

$keytool -export -v \
  -alias $lkalias \
  -file $lcertname \
  -keypass $lkeypass \
  -storepass $lkspass \
  -keystore $lksname \
  -rfc
}



# Create a server certificate, tied to test.com
function create_serv_cert
{
ldname=$1
lksname=$2
lkalias=$3
lkeypass=$4
lkspass=$5

echo "Creating server certificate to be named $lksname ... \n"

$keytool -genkeypair -v \
  -alias $lkalias \
  -dname $ldname \
  -keystore $lksname \
  -keypass $lkeypass \
  -storepass $lkspass \
  -keyalg RSA \
  -keysize 2048 \
  -validity 385
}

# Create a certificate signing request for test.com
function create_cert_request
{ 
lksname=$1
lkalias=$2
lkeypass=$3
lkspass=$4
lcsrname=$5

echo "Creating cert request to be named $lcsrname ... \n"

$keytool -certreq -v \
  -alias $lkalias \
  -keypass $lkeypass \
  -storepass $lkspass \
  -keystore $lksname \
  -file $lcsrname
}


# Tell testCA to sign the test.com certificate. Note the extension is on the request, not the
# original certificate.
# Technically, keyUsage should be digitalSignature for DHE or ECDHE, keyEncipherment for RSA.
function sign_cert
{
lcaksname=$1
lcaalias=$2
lcakspass=$3
lcsrname=$4
lcertname=$5
lksalias=$6

echo "Signing certificate to be named $lcertname based on passed in CSR named $lcsrname ... \n"

$keytool -gencert -v \
  -alias $lcaalias \
  -keypass $lcakspass \
  -storepass $lcakspass \
  -keystore $lcaksname \
  -infile $lcsrname \
  -outfile $lcertname \
  -ext KeyUsage:critical="digitalSignature,keyEncipherment" \
  -ext EKU="serverAuth" \
  -ext SAN="DNS:$lksalias" \
  -rfc
}


# Tell test.com.jks it can trust testca as a signer.
function import_ca_cert
{
lksname=$1
lcaalias=$2
lkspass=$3
lcacertname=$4

echo "importing root CA certificate named $lcacertname into keystore named $lksname ... \n"

$keytool -import -v \
  -alias $lcaalias \
  -file $lcacertname \
  -trustcacerts \
  -keystore $lksname \
  -storetype JKS \
  -storepass $lkspass << EOF
yes
EOF
}

# Import the signed certificate back into test.com.jks 
function import_signed_cert
{
lksname=$1
lalias=$2
lkspass=$3
lcertname=$4

echo "importing signed certificate named $lcertname into keystore named $lksname ... \n"

$keytool -import -v \
  -alias $lalias \
  -file $lcertname \
  -keystore $lksname \
  -storetype JKS \
  -storepass $lkspass
}

# List out the contents of test.com.jks just to confirm it.  
# If you are using Play as a TLS termination point, this is the key store you should present as the server.
function list_ks_content
{
lksname=$1
lkspass=$2

echo "Listing content of keystore named $lksname with passed in pwd $lkspass ... \n"

$keytool -list -v \
  -keystore $lksname \
  -storepass $lkspass

}


# Export test.com's public certificate.
function export_pub_cert
{
lksname=$1
lkalias=$2
lkeypass=$3
lkspass=$4
lcertname=$5

echo "Exporting public certificate named $lcertname from keystore named $lksname  with passed in kspwd $lkspass ... \n"

$keytool -export -v \
  -alias $lkalias \
  -file $lcertname \
  -keypass $lkeypass \
  -storepass $lkspass \
  -keystore $lksname \
  -rfc
}

# Create a PKCS#12 keystore containing the public and private keys.
function export_pkcs12_cert
{
lksname=$1
lkalias=$2
lkeypass=$3
lkspass=$4
lp12ksname=$5

echo "Exporting keystore named $lksname to PKCS12 keystore to be named $lp12ksname ... \n"

$keytool -importkeystore -v \
  -srcalias $lkalias \
  -srckeystore $lksname \
  -srcstoretype jks \
  -srckeypass $lkspass \
  -srcstorepass $lkspass \
  -destkeystore $lp12ksname \
  -destkeypass $lkeypass \
  -deststorepass $lkspass \
  -deststoretype PKCS12
}

# Export the test.com private key.  Note this requires the use of OpenSSL.
function export_pkcs12_cert_key
{
lkeypass=$1
lkeyfilename=$2
lp12ksname=$3

echo "Exporting private key to be named $lkeyfilename from PKCS12 keystore named $lp12ksname ... \n"

openssl pkcs12 \
  -nocerts \
  -nodes \
  -passout pass:$lkeypass \
  -passin pass:$lkeypass \
  -in $lp12ksname \
  -out $lkeyfilename

}


# Create a JKS keystore that trusts the test CA, with the default password.
function create_truststore_with_ca
{
lcacertname=$1
lcaalias=$2
lcakeypass=$3
ltsname=$4
ltspass=$5

echo "Creating a truststore to be named $ltsname using the CA ... \n"

$keytool -import -v \
  -alias $lcaalias \
  -file $lcacertname \
  -keypass $lcakeypass \
  -storepass $ltspass \
  -keystore $ltsname << EOF
yes
EOF
}


function create_user_certificate
{

lcakeyname=$1
lcacertname=$2
usrname=$3
usrpasswd=$4
lcakspass=$5
lcntrcode=$6
lusrcertkey=${usrname}.key
lusrcertcsr=${usrname}.csr
lusrcertfile=${usrname}.crt
lusrcertp12file=${usrname}.p12
lusrconfigfile=${usrname}.config
llocal="Denver"
lou="TestOrg"
lst="Colorado"
lo="TestCompany"

echo "Creating User Certificate $usrname.p12 for user named $usrname  ... \n"

 # generate the user's config file
 echo dir=. > ${lusrconfigfile}
 echo [ req ] >> ${lusrconfigfile}
 echo output_password=pass:${usrpasswd} >> ${lusrconfigfile}
 echo input_password=pass:${usrpasswd} >> ${lusrconfigfile}
 echo distinguished_name = req_distinguished_name >> ${lusrconfigfile}
 echo prompt=no >> ${lusrconfigfile}
 echo [ req_distinguished_name ]  >> ${lusrconfigfile}
 echo organizationName=${lo} >> ${lusrconfigfile}
 echo organizationalUnitName=${lou} >> ${lusrconfigfile}
 echo emailAddress=${usrname} >> ${lusrconfigfile}
 echo localityName=${llocal} >> ${lusrconfigfile}
 echo stateOrProvinceName=${lst} >> ${lusrconfigfile}
 echo commonName=${usrname} >> ${lusrconfigfile}
 echo countryName=${lcntrcode} >> ${lusrconfigfile}

 # generate the user's RSA private key
 openssl genrsa -des3 -out ${lusrcertkey} -passout pass:${usrpasswd} 4096 
	
 # generate a request for a user certificate 
 openssl req -new -key ${lusrcertkey} -passin pass:${usrpasswd} -out ${lusrcertcsr} -config ${lusrconfigfile}
	
 # sign request
 openssl x509 -req -days 365 -in ${lusrcertcsr} -CA ${lcacertname} -CAkey ${lcakeyname} -passin pass:${lcakspass} -set_serial ${RANDOM} -out ${lusrcertfile}  
	
 # export to p12 file	
 openssl pkcs12 -in ${lusrcertfile} -inkey ${lusrcertkey} -out ${lusrcertp12file} -export -name "${usrname}"  -passin pass:${usrpasswd} -passout pass:${usrpasswd}

 rm ${lusrconfigfile}

 echo -e "\n*******************************************************\n"
 echo The certificate for your user to import into his/her browser is ${lusrcertp12file} in `pwd`.  The password to import the file into the browser is ${usrpasswd}.
 echo -e "\n*******************************************************\n"
}

certsdir="wscerts"

javaHome=`echo $JAVA_HOME`

if [ -z "$javaHome" ]; then 
echo "JAVA_HOME needs to be set before running this script as it depends on java provided $$keytool. Please set it and re-run the script."
exit
fi

keytool=$javaHome/bin/keytool

mkdir $certsdir
if [ $? -ne 0 ]
then
echo "Delete ./$certsdir or rename it before running this script."
exit
fi

cd $certsdir

export dname="CN=testCA,OU=TestOrg,O=TestCompany,L=Denver,ST=Colorado,C=US"
export caksname="testca.jks"
export servcertdname="CN=localhost,OU=TestOrg,O=TestCompany,L=Denver,ST=Colorado,C=US"
export capwd="rootcapwd"
export caalias="ca"
export cacert="testca.crt"
export cap12ks="testca.p12"
export cakey="testca.key"
export ksname="localhost.jks"
export keyalias="localhost"
export keypass="password"
export kspass="password"
export kscsr="localhost.csr"
export kscert="localhost.crt"
export kspubcert="localhost.crt"
export p12ks="localhost.p12"
export kskey="localhost.key"
export tsname="truststore.jks"
export tskeypass="changeit"
export tspass="changeit"
export countrycode="US"
export usrpasswd="password"
export usrname1="testuser"
export usrname2="testadmin"
export usrname3="testsuperuser"

create_self_signing_cert_authority $dname $caksname $caalias $capwd $capwd
export_cert $caksname $caalias $capwd $capwd $cacert
create_serv_cert $servcertdname $ksname $keyalias $keypass $kspass
create_cert_request $ksname $keyalias $keypass $kspass $kscsr
sign_cert $caksname $caalias $capwd $kscsr $kscert $keyalias
import_ca_cert $ksname $caalias $kspass $cacert
import_signed_cert $ksname $keyalias $kspass $kscert
list_ks_content $ksname $kspass
export_pub_cert $ksname $keyalias $keypass $kspass $kspubcert
export_pkcs12_cert $caksname $caalias $capwd $capwd $cap12ks
export_pkcs12_cert_key $capwd $cakey $cap12ks
export_pkcs12_cert $ksname $keyalias $keypass $kspass $p12ks
export_pkcs12_cert_key $keypass $kskey $p12ks
create_truststore_with_ca $cacert $caalias $capwd $tsname $tspass
list_ks_content $tsname $tspass

create_user_certificate $cakey $cacert $usrname1 $usrpasswd $capwd $countrycode
create_user_certificate $cakey $cacert $usrname2 $usrpasswd $capwd $countrycode
create_user_certificate $cakey $cacert $usrname3 $usrpasswd $capwd $countrycode

#import_signed_cert $tsname $usrname1 ${usrname1}.crt $tskeypass
#import_signed_cert $tsname $usrname2 ${usrname2}.crt $tskeypass
#import_signed_cert $tsname $usrname3 ${usrname3}.crt $tskeypass

chmod 755 *

