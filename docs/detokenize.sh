#!/usr/bin/bash

cd

# test for existing Eclipse installation

ECLIPSE_START=$HOME/eclipse/java-2024-09/eclipse/eclipse
DIR1="${HOME}/eclipse"
DIR2="${HOME}/.p2"
DIR3="${HOME}/Echomix-workspace"
FAILURE="n"

if [ -d $DIR1 ]; then
    echo "Directory ${DIR1} from existing Eclipse installation found."
    echo "Remove directories eclipse, .p2, and *-workspace and try again."
    exit 1
fi

if [ -d $DIR2 ]; then
    echo "Directory ${DIR2} from existing Eclipse installation found."
    echo "Remove directories eclipse, .p2, and *-workspace and try again."
    exit 1 
fi

if [ -d $DIR3 ]; then
    echo "Directory ${DIR3} from existing Eclipse installation found."
    echo "Remove directories eclipse, .p2, and *-workspace and try again."
    exit 1 
fi

echo "What is the relative path, from your home directory, to your local katzenpost git repository?"
echo "(e.g., git/katzenpost)"

echo "Type the path:"

read -r GITPATH

echo

if [ -d $GITPATH ]; then

echo "Git path is valid, proceeding...."

else

echo "Invalid git path. Aborting. Determine the correct path and try again."

exit 1

fi

echo "* extracting archive"

gunzip -dc ~/collaborative_eclipse.tar.gz | tar xvf -

# First set the git path

echo "* setting git path"

find ~/Echomix-workspace-temp/.metadata/.plugins/org.eclipse.core.runtime/.settings/org.eclipse.egit.core.prefs -type f -exec sed -i "s|AAAtokenZZZ|${HOME}/${GITPATH}/|g" {} \;
find ~/Echomix-workspace-temp/.metadata/.plugins/org.eclipse.ui.ide/dialog_settings.xml -type f -exec sed -i "s|AAAtokenZZZ|${HOME}/${GITPATH}/|g" {} \;

# /home/$USER (file content)

echo "* detokenizing file content"

find ~/eclipse-temp -type f -exec sed -i "s|\/home\/AAAtokenZZZ|${HOME}|g" {} \;
find ~/.p2-temp -type f -exec sed -i "s|\/home\/AAAtokenZZZ|${HOME}|g" {} \;
find ~/Echomix-workspace-temp -type f -exec sed -i "s|\/home\/AAAtokenZZZ|${HOME}|g" {} \;

# _home_$USER (file content)

find ~/eclipse-temp -type f -exec sed -i "s|_home_AAAtokenZZZ|_home_${USER}|g" {} \;
find ~/.p2-temp -type f -exec sed -i "s|_home_AAAtokenZZZ|_home_${USER}|g" {} \;

echo "* detokenizing directory names"

# _home_$USER (directory names)

mv "${HOME}/.p2-temp/org.eclipse.equinox.p2.engine/profileRegistry/_home_AAAtokenZZZ_eclipse_~_eclipse_java-2024-09_eclipse.profile" "${HOME}/.p2-temp/org.eclipse.equinox.p2.engine/profileRegistry/_home_${USER}_eclipse_~_eclipse_java-2024-09_eclipse.profile"
mv "${HOME}/.p2-temp/org.eclipse.equinox.p2.engine/profileRegistry/_home_AAAtokenZZZ_eclipse_java-2024-09_eclipse.profile" "${HOME}/.p2-temp/org.eclipse.equinox.p2.engine/profileRegistry/_home_${USER}_eclipse_java-2024-09_eclipse.profile"





mv $HOME/eclipse-temp $HOME/eclipse
mv $HOME/.p2-temp $HOME/.p2
mv $HOME/Echomix-workspace-temp $HOME/Echomix-workspace

echo 
echo "Installation complete. Start Eclipse?"
echo
echo "y/n:"

read $START

if [[ $START == "y" ]]; then

$ECLIPSE_START

exit 1

fi

