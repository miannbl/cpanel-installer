yum update -y
yum install epel-release -y
yum install vim screen -y

script=$(sh ./main.sh)

screen -S cpanel "$script"
