#!/usr/bin/bash

cd

cp -r $HOME/eclipse $HOME/eclipse-temp
cp -r $HOME/.p2 $HOME/.p2-temp
cp -r $HOME/Echomix-workspace $HOME/Echomix-workspace-temp

# First tokenize the $GITPATH

find $HOME/.metadata/.plugins/org.eclipse.core.runtime/.settings/org.eclipse.egit.core.prefs -type f -exec sed -i "s|${HOME}\/git\/katzenpost|AAAtokenZZZ|g" {} \;
find $HOME/.metadata/.plugins/org.eclipse.ui.ide/dialog_settings.xml -type f -exec sed -i "s|${HOME}\/git\/katzenpost|AAAtokenZZZ|g" {} \;

# /home/$USER (file content)

find $HOME/eclipse-temp -type f -exec sed -i "s|${HOME}|\/home\/AAAtokenZZZ|g" {} \;
find $HOME/.p2-temp -type f -exec sed -i "s|${HOME}|\/home\/AAAtokenZZZ|g" {} \;
find $HOME/Echomix-workspace-temp -type f -exec sed -i "s|${HOME}|\/home\/AAAtokenZZZ|g" {} \;

# _home_$USER (file content)

$HOME/find eclipse-temp -type f -exec sed -i "s|_home_${USER}|_home_AAAtokenZZZ|g" {} \;
$HOME/find .p2-temp -type f -exec sed -i "s|_home_${USER}|_home_AAAtokenZZZ|g" {} \;

# _home_$USER (directory names)

# $USER@skamander:~$ find .p2 -name "_home_${USER}*"
# .p2/org.eclipse.equinox.p2.engine/profileRegistry/_home_$USER_eclipse_~_eclipse_java-2024-09_eclipse.profile
# .p2/org.eclipse.equinox.p2.engine/profileRegistry/_home_$USER_eclipse_java-2024-09_eclipse.profile

mv "${HOME}/.p2-temp/org.eclipse.equinox.p2.engine/profileRegistry/_home_${USER}_eclipse_~_eclipse_java-2024-09_eclipse.profile" "${HOME}/.p2-temp/org.eclipse.equinox.p2.engine/profileRegistry/_home_AAAtokenZZZ_eclipse_~_eclipse_java-2024-09_eclipse.profile"
mv "${HOME}/.p2-temp/org.eclipse.equinox.p2.engine/profileRegistry/_home_${USER}_eclipse_java-2024-09_eclipse.profile" "${HOME}/.p2-temp/org.eclipse.equinox.p2.engine/profileRegistry/_home_AAAtokenZZZ_eclipse_java-2024-09_eclipse.profile"

# Why is this even there, recording random system information?

rm -r $HOME/Echomix-workspace-temp/.metadata/.plugins/org.eclipse.core.resources/.history/

tar -czf $HOME/collaborative_eclipse.tar.gz $HOME/eclipse-temp $HOME/.p2-temp $HOME/Echomix-workspace-temp

rm -r $HOME/eclipse-temp $HOME/.p2-temp $HOME/Echomix-workspace-temp
