#!/bin/bash
DB_NAMES=(wp_db1 wp_db2 wp_db3)
DB_USERS=(wp_user1 wp_user2 wp_user3)
hosts=(site1.com site2.com site3.com)
apache_path="/etc/apache2/sites-available/"
apache_ports="/etc/apache2/ports.conf"
apache_log_dir="/var/log/apache2"
result=0
nginx_path="/etc/nginx/sites-available/"
nginx_path_enabled="/etc/nginx/sites-enabled/"
nginx_ssl_path="/etc/nginx/ssl"
nginx_ssl_crt="ssl-k.crt"
nginx_ssl_key="ssl-k.key"
proxy_set_header_host="$""host"
request_uri="$""request_uri"
colors=("#FF0000" "#00FF00" "#0000FF")
path_www="/var/www"
current_perm=$(stat -c "%a" "$path_www")
current_own=$(stat -c "%U" "$path_www")
current_group=$(stat -c "%G" "$path_www")
default_color="#f5f5f5"
default_path_color="wp-admin/css/colors/light/colors-rtl.css"
wp_content="wp-content/uploads"
wp_config_simple="wp-config-sample.php"
wp_config="wp-config.php"
password='password'
wp_siteurl="'WP_SITEURL'"
wp_home="'WP_HOME'"
wp_ser="$""_SERVER"

#install
if ! dpkg -l | grep -E 'nginx|apache2|php|mysql-server|php-mysql'; then
    sudo apt update
    sudo apt install -y nginx apache2 php php-mysql mysql-server
fi

#mysql
for (( i = 0; i < "${#DB_NAMES[*]}"; i++ ))
do
  if ! mysql -uroot -e "USE ${DB_NAMES[i]}" 2>/dev/null; then
    mysql -uroot -e "CREATE DATABASE ${DB_NAMES[i]};"
  fi
  if ! mysql -uroot -e "SELECT User FROM mysql.user WHERE User='${DB_USERS[i]}'" | grep "${DB_USERS[i]}"; then
    mysql -uroot -e "CREATE USER '${DB_USERS[i]}'@'localhost' IDENTIFIED BY 'password';"
    mysql -uroot -e "GRANT ALL PRIVILEGES ON ${DB_NAMES[i]}.* TO '${DB_USERS[i]}'@'localhost';"
    mysql -uroot -e "FLUSH PRIVILEGES;"
  fi
done

#apache2
for (( i = 0; i < "${#hosts[*]}"; i++ )); do
  info_apache=$(cat << EOF
<VirtualHost *:8080>
        ServerName ${hosts[i]}
        ServerAlias www.${hosts[i]}

        ServerAdmin ${hosts[i]}-webmaster@localhost
        DocumentRoot /var/www/${hosts[i]}

        ErrorLog $apache_log_dir/${hosts[i]}-error.log
        CustomLog $apache_log_dir/${hosts[i]}-access.log combined
</VirtualHost>
EOF
)

  for file in "$apache_path"*; do
    filename=$(basename "$file")
    if [[ "$filename" == "${hosts[i]}.conf" ]]; then
      result=1
      echo "File ${hosts[i]}.conf was found"
    fi
  done

    if ! grep -q "Listen 8080" "${apache_ports}"; then
      sudo sed -i 's/Listen 80/Listen 8080/' "${apache_ports}"
    fi
    if [[ "$result" = 0 ]]; then
      touch "${apache_path}${hosts[i]}.conf"
      echo "$info_apache" > "${apache_path}${hosts[i]}.conf"
      sudo a2dissite 000-default.conf
      sudo a2ensite "${hosts[i]}"
      result=0
      sudo systemctl restart apache2
    fi
  if diff -b -w -B <(echo "$info_apache") "${apache_path}${hosts[i]}.conf" >/dev/null; then
    echo "file equal"
  else
    echo "$info_apache" > "${apache_path}${hosts[i]}.conf"
  fi
done

#nginx
result=""


for (( i = 0; i < "${#hosts[*]}"; i++ ))
do

info_https=$(cat <<EOF

server {
	server_name www.${hosts[i]} ${hosts[i]};
        
	location / {
		include /etc/nginx/proxy_params;
                proxy_pass http://localhost:8080;
        }

	listen 443 ssl;
	ssl_certificate ${nginx_ssl_path}/${nginx_ssl_crt};
        ssl_certificate_key ${nginx_ssl_path}/${nginx_ssl_key};
}

server {
	listen 80;
	server_name www.${hosts[i]} ${hosts[i]};
	return 301 https://$proxy_set_header_host$request_uri;
}
EOF
)
result+="$info_https"
done


if ! [ -d "${nginx_ssl_path}" ]; then
  sudo mkdir "${nginx_ssl_path}"
  sudo chmod 700 "${nginx_ssl_path}"
  if ! [ -f "${nginx_ssl_path}/${nginx_ssl_key}"]; then
    sudo touch "${nginx_ssl_path}/${nginx_ssl_key}"
  fi
  if ! [ -f "${nginx_ssl_path}/${nginx_ssl_crt}"]; then
    sudo touch "${nginx_ssl_path}/${nginx_ssl_key}"
  fi
  sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 -keyout "${nginx_ssl_path}/${nginx_ssl_key}" -out "${nginx_ssl_path}/${nginx_ssl_crt}"
fi
if  [ -f "${nginx_path_enabled}default" ]; then
  sudo rm -f "${nginx_path_enabled}default"
fi
if  [ -f "${nginx_path}default" ]; then
  sudo rm "${nginx_path}default"
fi
if  [ -f "${nginx_path}https" ]; then
  if diff -b -w -B <(echo "$result") https >/dev/null; then
  echo "variable and file are equal"
  fi
else
  sudo touch "${nginx_path}https"
  echo "$result" > "${nginx_path}https"
  sudo ln -s "${nginx_path}https" "${nginx_path_enabled}https"
  sudo systemctl restart nginx.service
fi

#wordpress
https_wp=$(cat << EOF
if ( $wp_ser['HTTP_X_FORWARDED_PROTO'] == 'https' )
{
        $wp_ser['HTTPS']       = 'on';
    $wp_ser['SERVER_PORT'] = '443';
        define('FORCE_SSL_ADMIN', true);
}
 
if ( isset($wp_ser['HTTP_X_FORWARDED_HOST']) )
{
        $wp_ser['HTTP_HOST'] = $wp_ser['HTTP_X_FORWARDED_HOST'];
}
EOF
)

#echo "$https_wp"
if  [ ! -f "https_wp.txt" ]; then
  sudo touch https_wp.txt
  sudo chmod 777 https_wp.txt
  echo "$https_wp" > https_wp.txt </dev/null
fi
if [ ! -d "$path_www/wordpress" ]; then
  wget https://wordpress.org/latest.tar.gz -P /tmp/
  sudo tar -xvf /tmp/latest.tar.gz -C $path_www
fi

for (( i = 0; i < "${#hosts[*]}"; i++ ))
do
  if [ ! -d "$path_www/${hosts[i]}" ]; then
    cp -r $path_www/wordpress $path_www/${hosts[i]}
    mkdir $path_www/${hosts[i]}/$wp_content
  fi
  if [ ! -f "$path_www/${hosts[i]}/$wp_config" ];then
     cp $path_www/${hosts[i]}/$wp_config_simple $path_www/${hosts[i]}/$wp_config
  fi
  if grep -q "database_name_here" "$path_www/${hosts[i]}/$wp_config"; then
    sudo sed -i "s/database_name_here/${DB_NAMES[i]}/" $path_www/${hosts[i]}/$wp_config
  fi
  if grep -q "username_here" "$path_www/${hosts[i]}/$wp_config"; then
    sudo sed -i "s/username_here/${DB_USERS[i]}/" $path_www/${hosts[i]}/$wp_config
  fi
  if grep -q "password_here" "$path_www/${hosts[i]}/$wp_config"; then
    sudo sed -i "s/password_here/${password}/" $path_www/${hosts[i]}/$wp_config
  fi
  if ! grep -q "$wp_siteurl" "$path_www/${hosts[i]}/$wp_config"; then
    sudo sed -i '1 a\define( '$wp_siteurl', '"'https://www.${hosts[i]}'"' );' $path_www/${hosts[i]}/$wp_config
  fi
  if ! grep -q "$wp_home" "$path_www/${hosts[i]}/$wp_config"; then
    sudo sed -i '2 a\define( '$wp_home', '"'https://www.${hosts[i]}'"' );' $path_www/${hosts[i]}/$wp_config
  fi
  if ! grep -Fqx "$https_wp" "$path_www/${hosts[i]}/$wp_config"; then
    sudo sed -i "3r https_wp.txt" $path_www/${hosts[i]}/$wp_config
  fi
  done
  if [[ "$current_prem" -gt 755 ]]; then
  sudo chmod -R 755 $path_www/
fi
if [[ "$current_own" -ne "www-data" ]] || [[ "$current_group" -ne "www-data" ]]; then
  sudo chown -R www-data:www-data $path_www/
fi
