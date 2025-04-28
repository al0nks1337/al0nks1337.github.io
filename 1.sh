#!/bin/bash

# Prompt for the new username
read -p "Enter the username for the new sudo user: " USERNAME

# Check if the user already exists
if id "$USERNAME" &>/dev/null; then
    echo "User '$USERNAME' already exists. Skipping user creation."
else
    # Create the user
    echo "Creating user '$USERNAME'..."
    sudo adduser "$USERNAME"

    # Assign sudo privileges to the user
    echo "Adding user '$USERNAME' to the sudo group..."
    if sudo usermod -aG sudo "$USERNAME"; then
        echo "User '$USERNAME' created and added to the sudo group successfully."
    else
        echo "Failed to add user '$USERNAME' to the sudo group."
    fi
fi

# Prompt the user to enter a port number
read -p "Please enter the new SSH port: " NEW_PORT

# Validate if the input is a valid number
if [[ "$NEW_PORT" =~ ^[0-9]+$ ]]; then
    # Stop the VNC server service
    echo "Stopping the VNC server service (vncserver-x11-serviced)..."
    if sudo systemctl stop vncserver-x11-serviced; then
        echo "VNC server service stopped successfully."
    else
        echo "Failed to stop the VNC server service. Continuing with SSH configuration update..."
    fi

    # Define the SSH configuration file path
    CONFIG_FILE="/etc/ssh/sshd_config"

    # Check if the file exists
    if [[ -f "$CONFIG_FILE" ]]; then
        # Use sed to replace "#Port 22" with "Port <NEW_PORT>"
        sudo sed -i "s/^#Port 22$/Port $NEW_PORT/" "$CONFIG_FILE"

        # Check if the replacement was successful
        if grep -q "^Port $NEW_PORT$" "$CONFIG_FILE"; then
            echo "The SSH port has been successfully updated to $NEW_PORT."

            # Restart the SSH service to apply changes
            echo "Restarting the SSH service..."
            if sudo systemctl restart sshd; then
                echo "SSH service restarted successfully."
            else
                echo "Failed to restart the SSH service. Please check manually."
            fi
        else
            echo "Failed to update the SSH port. Please check the file $CONFIG_FILE."
        fi
    else
        echo "Error: The file $CONFIG_FILE does not exist."
    fi
else
    echo "Invalid input. Please enter a valid numeric port number."
fi

# Close the terminal after completion
echo "All tasks completed. Closing the terminal in 5 seconds..."
sleep 5
exit
