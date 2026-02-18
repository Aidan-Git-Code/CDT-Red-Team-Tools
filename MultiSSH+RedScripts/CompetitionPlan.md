# Hi Team

This is the plan that I have for the deployment

This tool can deploy any tool folder and install script using the
### ./deploy_tool.sh <config.yaml> <local_tool_directory> <remote_dir> <install_command / script>
restrictions may apply*

Some possible directories:
- Any folder in /etc/, especially the boring looking ones like gss/mech.d/
- Any conf files they might not check
- /bins/ or /bin/ or /usr/share/ 
- /lib/ <--- This is where I will go
- some persistence will end up in /tmp/ as well but that's not too important