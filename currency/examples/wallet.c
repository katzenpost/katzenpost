/*
 wallet.c - Katzenpost example C wallet client.
 Copyright (C) 2018  David Stainton.

 This program is free software: you can redistribute it and/or modify
 it under the terms of the GNU Affero General Public License as
 published by the Free Software Foundation, either version 3 of the
 License, or (at your option) any later version.

 This program is distributed in the hope that it will be useful,
 but WITHOUT ANY WARRANTY; without even the implied warranty of
 MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 GNU Affero General Public License for more details.

 You should have received a copy of the GNU Affero General Public License
 along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#include "currency_bindings.h"
#include "client_bindings.h"


int main(int argc, char *argv[]) {
  char ticker[3];
  strcpy(ticker, "ZEC");
  char tx[500];
  strcpy(tx, "0400008085202f89019d43a611ab6a5c9ba8deb2c06b3ba84bef1467c1e89e37104b36bf8def76e348010000006a47304402207d9c322933339029be227be3e0bfbb6b73356eb4182e1a6e4f201f525f18cc9f0220194c4ed2f4ad231b36f917fed79c0806fddbdbb765880e39f806f47284828392012102941105444fc19a2d1a9893c6d30f41a49e33964021d35f9c777d3c668202a37bfeffffff021774b010000000001976a914f820a2dd16cd16cd24eefd1b5cbde6736c6840ac88ac80969800000000001976a91446d6310563200e264862184078f21930272084c588ac68d0050087d005000000000000000000000000");
  char *request;
  request = NewRequest(ticker, tx);
  printf("sending request %s\n", request);

  LoadConfig(argv[1]);
  NewClient();
  Start();
  QueryAvailableService("zec", request, strlen(request));
  Stop();

  free(request);
  return 0;
}
