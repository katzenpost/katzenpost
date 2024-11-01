#!/usr/bin/bash

echo
echo "This script purges user-specific strings in the directories and files"
echo "of the local existing Eclipse installation and inserts tokens in their place."
echo

cd

echo "* preparing temp files"

cp -r $HOME/eclipse $HOME/eclipse-temp
cp -r $HOME/.p2 $HOME/.p2-temp
cp -r $HOME/Echomix-workspace $HOME/Echomix-workspace-temp

echo "* tokenizing git path"

# First tokenize the $GITPATH

find $HOME/.metadata/.plugins/org.eclipse.core.runtime/.settings/org.eclipse.egit.core.prefs -type f -exec sed -i "s|${HOME}\/git\/katzenpost|AAAtokenZZZ|g" {} \;
find $HOME/.metadata/.plugins/org.eclipse.ui.ide/dialog_settings.xml -type f -exec sed -i "s|${HOME}\/git\/katzenpost|AAAtokenZZZ|g" {} \;

echo "* tokenizing file contents"

# /home/$USER (file content)

find $HOME/eclipse-temp -type f -exec sed -i "s|${HOME}|\/home\/AAAtokenZZZ|g" {} \;
find $HOME/.p2-temp -type f -exec sed -i "s|${HOME}|\/home\/AAAtokenZZZ|g" {} \;
find $HOME/Echomix-workspace-temp -type f -exec sed -i "s|${HOME}|\/home\/AAAtokenZZZ|g" {} \;

# _home_$USER (file content)

find $HOME/eclipse-temp -type f -exec sed -i "s|_home_${USER}|_home_AAAtokenZZZ|g" {} \;
find $HOME/.p2-temp -type f -exec sed -i "s|_home_${USER}|_home_AAAtokenZZZ|g" {} \;

echo "* tokenizing directory names"

# _home_$USER (directory names)

# $USER@skamander:~$ find .p2 -name "_home_${USER}*"
# .p2/org.eclipse.equinox.p2.engine/profileRegistry/_home_$USER_eclipse_~_eclipse_java-2024-09_eclipse.profile
# .p2/org.eclipse.equinox.p2.engine/profileRegistry/_home_$USER_eclipse_java-2024-09_eclipse.profile

mv "${HOME}/.p2-temp/org.eclipse.equinox.p2.engine/profileRegistry/_home_${USER}_eclipse_~_eclipse_java-2024-09_eclipse.profile" "${HOME}/.p2-temp/org.eclipse.equinox.p2.engine/profileRegistry/_home_AAAtokenZZZ_eclipse_~_eclipse_java-2024-09_eclipse.profile"
mv "${HOME}/.p2-temp/org.eclipse.equinox.p2.engine/profileRegistry/_home_${USER}_eclipse_java-2024-09_eclipse.profile" "${HOME}/.p2-temp/org.eclipse.equinox.p2.engine/profileRegistry/_home_AAAtokenZZZ_eclipse_java-2024-09_eclipse.profile"

# Why is this even there, recording random system information?

echo "* removing history directory, if any"



rm -r $HOME/Echomix-workspace-temp/.metadata/.plugins/org.eclipse.core.resources/.history/

echo "* tarring, zipping"

cd

tar -czf collaborative_eclipse.tar.gz eclipse-temp .p2-temp Echomix-workspace-temp

echo "* cleaning up temp files"

rm -r eclipse-temp .p2-temp Echomix-workspace-temp

echo
echo "DONE! Compressed archive collaborative_eclipse.tar.gz is ready for expost."
