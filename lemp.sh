#!/bin/bash

#Auxiliary variables
ip_address=`ip a | grep 'inet ' | grep -v '127.0.0.1' | tail -1 | awk '{print $2}' | cut -d '/' -f 1`
path_to_www="/var/www"
domain_name="task2-up4soft.test"

#Database variables
database_name="wordpress"
database_user="wp"
database_password="password"

#Apache2 variables
apache_path_ports_conf="/etc/apache2/ports.conf"
apache_path_config="/etc/apache2/sites-available/000-default.conf"
apache_running_port="8080"
apache_current_port="80"
apache_current_document_root="$path_to_www/html"
apache_running_document_root="$path_to_www/$database_name"


#Nginx variables
nginx_path_config="/etc/nginx/sites-available/default"
nginx_path_cert="/etc/nginx/ssl"
nginx_public_key="ssl.crt"
nginx_private_key="ssl.key"
nginx_supporting_variable='$host$request_uri' #this variable is needed to add the string 'return 301 https://$host$request_uri;' correctly
nginx_config_file="server {
        listen 443 ssl;
        server_name www.$domain_name $domain_name;

        ssl_certificate $nginx_path_cert/$nginx_public_key;
        ssl_certificate_key $nginx_path_cert/$nginx_private_key;

        location /wordpress/ {
                proxy_pass http://localhost:8080/;
                include /etc/nginx/proxy_params;
        }

        location /site {
                root $path_to_www;
        }
}

server {
        listen 80;
        server_name www.$domain_name $domain_name;
        return 301 https://$nginx_supporting_variable;
}"

#Wordpress variables
site_context_first="wordpress"
site_context_second="site"
wp_config_name="wp-config.php"
wp_config_name_simple="wp-config-sample.php"
wp_config_https_context="\$_SERVER['REQUEST_URI'] = str_replace(\"/wp-admin/\", \"/wordpress/wp-admin/\",  \$_SERVER['REQUEST_URI']);\
if ( \$_SERVER['HTTP_X_FORWARDED_PROTO'] == 'https' )\
{\
        \$_SERVER['HTTPS']       = 'on';\
        \$_SERVER['SERVER_PORT'] = '443';\
        define('FORCE_SSL_ADMIN', true);\
}\
if ( isset(\$_SERVER['HTTP_X_FORWARDED_HOST']) )\
{\
        \$_SERVER['HTTP_HOST'] = \$_SERVER['HTTP_X_FORWARDED_HOST'];\
}"

#Created function for check and change smth
function change-value {
    sudo sed -i "$1" "$2"
}

function check-and-change-value-neg-condition {
    if ! grep -q "$1" "$2"; then
        change-value "$3" "$2"
    fi
}

function check-and-change-value-pos-condition {
    if grep -q "$1" "$2"; then
        change-value "$3" "$2"
    fi
}

#Add to sshd_config authentication without pass
check-and-change-value-neg-condition "PasswordAuthentication no" "/etc/ssh/sshd_config" "s/PasswordAuthentication yes/PasswordAuthentication no/g"

#Installation of nessesary softwares
if ! dpkg -l | grep -E 'nginx|apache2|php|mysql-server|php-mysql' >/dev/null; then
    sudo apt-get update
    sudo apt-get upgrade -y
    sudo apt-get install -y nginx apache2 php php-mysql mysql-server
    sudo systemctl restart sshd
fi

#Setting mysql service
if ! sudo mysql -e "USE $database_name" 2>/dev/null; then
    sudo mysql -e "CREATE DATABASE $database_name;"
fi

if ! sudo mysql -e "SELECT User FROM mysql.user WHERE User='$database_user'" | grep "$database_user" >/dev/null; then
    sudo mysql -e "CREATE USER '$database_user'@'localhost' IDENTIFIED BY 'password';"
    sudo mysql -e "GRANT ALL PRIVILEGES ON $database_name.* TO '$database_user'@'localhost';"
    sudo mysql -e "FLUSH PRIVILEGES;"
fi

#Setting apache change port and document root
check-and-change-value-neg-condition $apache_running_document_root $apache_path_config "s|$apache_current_document_root|$apache_running_document_root|g"
check-and-change-value-neg-condition $apache_running_port $apache_path_config "s/$apache_current_port/$apache_running_port/g"
check-and-change-value-neg-condition $apache_running_port $apache_path_ports_conf "s/$apache_current_port/$apache_running_port/g"

#Setting nginx create folder for ssl cert, generate cert and create new nginx config file for https running
if ! sudo test -d $nginx_path_cert; then
    sudo mkdir $nginx_path_cert
    sudo chmod 700 $nginx_path_cert
fi

if ! sudo test -f $nginx_path_cert/$nginx_public_key && ! sudo test -f $nginx_path_cert/$nginx_private_key; then
    sudo openssl req -x509 -nodes -days 365 -newkey rsa:4096 -keyout $nginx_path_cert/$nginx_private_key -out $nginx_path_cert/$nginx_public_key "/C=/ST=/L=/O=/OU=/CN="
fi

if ! echo "$nginx_config_file"  | diff - $nginx_path_config >/dev/null; then
     echo "$nginx_config_file" | sudo tee $nginx_path_config >/dev/null
fi

#Setting wordpress downoload and create context /site
if ! sudo test -d $path_to_www/$site_context_first; then
    wget https://wordpress.org/latest.tar.gz -P /tmp/
    sudo tar -xvf /tmp/latest.tar.gz -C $path_to_www
fi

if ! sudo test -f $path_to_www/$site_context_first/$wp_config_name; then
    sudo mv $path_to_www/$site_context_first/$wp_config_name_simple $path_to_www/$site_context_first/$wp_config_name
fi

if ! sudo test -d $path_to_www/$site_context_second; then
    sudo mkdir $path_to_www/$site_context_second
    echo "<h1>This is the task #2 </h1>" | sudo tee $path_to_www/$site_context_second/index.html >/dev/null
fi

#Change some values in wp-config.php using function
check-and-change-value-pos-condition "database_name_here" $path_to_www/$site_context_first/$wp_config_name "s/database_name_here/$database_name/"
check-and-change-value-pos-condition "username_here" $path_to_www/$site_context_first/$wp_config_name "s/username_here/$database_user/"
check-and-change-value-pos-condition "password_here" $path_to_www/$site_context_first/$wp_config_name "s/password_here/$database_password/"

check-and-change-value-neg-condition 'WP_SITEURL' $path_to_www/$site_context_first/$wp_config_name "1 a\define( 'WP_SITEURL', '"https://$domain_name/$site_context_first"' );"
check-and-change-value-neg-condition 'WP_HOME' $path_to_www/$site_context_first/$wp_config_name "2 a\define( 'WP_HOME', '"https://$domain_name/$site_context_first"' );"


if ! grep -qFx "$wp_config_https_context" $path_to_www/$site_context_first/$wp_config_name; then
    sed -i "4i $wp_config_https_context" $path_to_www/$site_context_first/$wp_config_name
fi

#Add to hosts file ip address and site url
check-and-change-value-neg-condition "^$ip_address" "/etc/hosts" "\$a$ip_address $domain_name www.$domain_name"

#Check nessesary permitions, owner and group
current_perm=$(stat -c "%a" "$path_to_www")
current_own=$(stat -c "%U" "$path_to_www")
current_group=$(stat -c "%G" "$path_to_www")

if [ "$current_perm" -lt 755 ]; then
  sudo chmod -R 755 "$path_to_www"
fi

if [[ $current_own != "www-data" ]] || [[ $current_group != "www-data" ]]; then
  sudo chown -R www-data:www-data "$path_to_www/"
  sudo systemctl enable nginx
  sudo systemctl enable apache2
  sudo systemctl restart apache2
  sudo systemctl restart nginx
fi

if ! [ "$(ufw status | grep 'Status: active')" ]; then
    sudo ufw enable
fi

ssh_port="22"
http_port="80"
https_port="443"

function allow-port {
    if ! sudo ufw status | grep "$1/tcp" >/dev/null; then
        sudo ufw allow $1/tcp
    fi
}

allow-port $ssh_port
allow-port $http_port
allow-port $https_port
