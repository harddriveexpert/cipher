#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "aktool.h"

#ifdef AK_HAVE_ERRNO_H
#include <errno.h>
#endif
#ifdef AK_HAVE_BZLIB_H
#include <bzlib.h>
#endif
#ifdef AK_HAVE_UNISTD_H
#include <unistd.h>
#endif

//if(aktool_check_command("cipher", argv[1])) return cipher_ss( argc, argv );
//cipher --audit 2 --audit-file stderr -b fffff.ke -a magma -e ctr -t text.crash -o out --in_file 16384 --out_file 20000


int aktool_cip_help( void ){
    printf(
            _("aktool key [options]  - key generation and management functions\n\n"
            ));
    printf(
            _(" -b, --bckey                 generate a new key or key pair for specified target\n"
              " -a, --algorithm_of_encrypt  choice of encryption algorithm (magma or kuznechik)\n"
              " -e, --encrypt_mode          select encryption mode\n"
              " -m, --sync_message          sync message generation\n"
              " -t, --target                read file for encryption\n"
              " -o, --out                   creating a file for writing encrypted information\n"
              "     --in_file               number of bytes where to start read file\n"
              "     --out_file              number of bytes where to end read file\n"
            ),
            aktool_default_generator);
    printf(
            _("options used for customizing a public key's certificate:\n"
            ));
    aktool_print_common_options();

    printf(_("for usage examples try \"man aktool\"\n" ));

    return EXIT_SUCCESS;
}




static int generation_of_sync_message(const char *sync_message){
    int errcount = 0, exitcode = EXIT_SUCCESS;
    struct random generator;
    ak_uint8 e[48];


    if( ak_random_create_lcg( &generator ) != ak_error_ok ) {
        aktool_error(_("problem with initialization of random"));
        errcount++;
        return EXIT_FAILURE;
    }
    for( int j = 0; j < 48; j++ ) {
        ak_random_ptr(&generator, &e[j], 8);
    }
    struct file write_file;
    if (ak_file_create_to_write( &write_file, sync_message) == ak_error_access_file){
        aktool_error(_("problem create file to write"));
        errcount++;
        return EXIT_FAILURE;
    }
    if (ak_file_write(&write_file, e, sizeof(e)) == ak_error_write_data){
        aktool_error(_("problem create file to write"));
        errcount++;
        return EXIT_FAILURE;
    }
    return exitcode;
}


static int cipher_encryption(const char *file_key, const char *algorithm_of_encrypt,
                             const char *encrypt_mode, const char *file, const char *file2,
                             const char *sync_message, int in_file, int out_file){
    int errcount = 0, exitcode = EXIT_SUCCESS;
    struct bckey key;
    ak_uint8 *addr = NULL;
    struct file key_file;
    struct signkey lkey;

    if ((strcmp (algorithm_of_encrypt, "magma") != 0) && (strcmp (algorithm_of_encrypt, "kuznechik") != 0)){
        aktool_error(_("The algorithm is incorrectly defined"));
        errcount++;
        return EXIT_FAILURE;
    }


    if (file_key == NULL){
        aktool_error(_("file_key information not set"));
        errcount++;
        return EXIT_FAILURE;
    } else{
        if (ak_file_open_to_read(&key_file, file_key) == ak_error_access_file){
            aktool_error(_("problem opening file for reading"));
            errcount++;
            return EXIT_FAILURE;
        }
        addr = ak_file_mmap(&key_file, NULL, key_file.size, PROT_READ, MAP_PRIVATE, 0);
        if(ak_error_get_value() != 0) {
            aktool_error(_("incorrect file_key data reading from file"));
            errcount++;
            return EXIT_FAILURE;
        } else {
            int key_chec = 0;
            if (strcmp (algorithm_of_encrypt, "magma") == 0){
                if((ak_bckey_create_magma( &key )) != ak_error_ok ) {
                    aktool_error(_("incorrect creation of magma secret key"));
                    errcount++;

                    return EXIT_FAILURE;
                } else{
                    if((ak_bckey_set_key(&key, addr, key_file.mmaped_size)) != ak_error_ok ) {
                        aktool_error(_("incorrect assigning a key value"));
                        errcount++;
                        ak_file_unmap( &key_file );
                        ak_file_close( &key_file );
                        ak_bckey_destroy( &key );
                        return EXIT_FAILURE;
                    } else{
                        key_chec = 1;
                    }
                }
            }
            if (strcmp (algorithm_of_encrypt, "kuznechik") == 0){
                if((ak_bckey_create_kuznechik( &key )) != ak_error_ok ) {
                    aktool_error(_("incorrect creation of magma secret key"));
                    errcount++;

                    return EXIT_FAILURE;
                } else{
                    if((ak_bckey_set_key(&key, addr, key_file.mmaped_size)) != ak_error_ok ) {
                        aktool_error(_("incorrect assigning a key value"));
                        errcount++;
                        ak_file_unmap( &key_file );
                        ak_file_close( &key_file );
                        ak_bckey_destroy( &key );
                        return EXIT_FAILURE;
                    } else{
                        key_chec = 1;
                    }
                }
            }
            if (key_chec == 0){
                aktool_error(_("Problem with creation of cay from file. Check name of encryption algorithm"));
                errcount++;
                return EXIT_FAILURE;
            }
        }
    }

    /*чтение данных*/

    ak_uint8 *addr2 = NULL;
    struct file target_file;
    if (ak_file_open_to_read(&target_file, file) == ak_error_access_file){
        aktool_error(_("problem opening file for reading"));
        errcount++;
        return EXIT_FAILURE;
    }


    int sz = getpagesize();
    long long offset = 0;
    long long length = target_file.size;
    if((in_file != 0) || (out_file != 0)){
        if((in_file > 0)){
            if((in_file % sz != 0) || (in_file > target_file.size)){
                printf("n_file must be a multiple %d\n", sz);
                aktool_error(_("problem with in_file"));
                errcount++;
                return EXIT_FAILURE;
            } else{
                offset = in_file;
                length = length - offset;

            }
        }

        if((out_file > 0)){
            if ((out_file > target_file.size) || (out_file < offset)){
                aktool_error(_("problem with out_file"));
                errcount++;
                return EXIT_FAILURE;
            } else{
                length = out_file - offset;
            }

        }
    }

    addr2 = ak_file_mmap(&target_file, NULL, length, PROT_READ, MAP_PRIVATE, offset);
    if(ak_error_get_value() != 0) {
        aktool_error(_("incorrect target data reading from file"));
        errcount++;
        return EXIT_FAILURE;
    }


/*чтение файла с синхропосылкой*/

    ak_uint8 *iv = NULL;
    struct file sync_message_file;
    if (ak_file_open_to_read(&sync_message_file, sync_message) == ak_error_access_file){
        aktool_error(_("problem opening file for reading"));
        errcount++;
        return EXIT_FAILURE;
    }
    iv = ak_file_mmap(&sync_message_file, NULL, sync_message_file.size, PROT_READ, MAP_PRIVATE, 0);
    if(ak_error_get_value() != 0) {
        aktool_error(_("incorrect file_key data reading from file"));
        errcount++;
        return EXIT_FAILURE;
    }





    static int work_of_encrypt = 0;
    size_t size = target_file.mmaped_size;
    ak_uint8 *data2 = malloc(size);




    if ((strcmp (encrypt_mode, "ecb") == 0)){
        int error;
        if((error = ak_bckey_encrypt_ecb(&key, addr2, data2, target_file.mmaped_size)) != ak_error_ok){
            aktool_error(("problem with encrypt_ecb %d"));
            printf("cod of error: %d\n", error);
            errcount++;
            return EXIT_FAILURE;
        } else{
            work_of_encrypt = 1;
        }
    }
    if ((strcmp (encrypt_mode, "ctr") == 0)){
        int error;
        if((error = ak_bckey_ctr(&key, addr2, data2, target_file.mmaped_size, iv, sizeof(iv))) != ak_error_ok){
            aktool_error(("problem with encrypt_ctr %d"));
            printf("cod of error: %d\n", error);
            errcount++;
            return EXIT_FAILURE;
        } else{
            work_of_encrypt = 1;
        }
    }
    if ((strcmp (encrypt_mode, "cbc") == 0)){
        int error;
        if((error = ak_bckey_encrypt_cbc(&key, addr2, data2, target_file.mmaped_size, iv, sizeof(iv))) != ak_error_ok){
            aktool_error(("problem with encrypt_cbc %d"));
            printf("cod of error: %d\n", error);
            errcount++;
            return EXIT_FAILURE;
        } else{
            work_of_encrypt = 1;
        }
    }
    if ((strcmp (encrypt_mode, "ofd") == 0)){
        int error;
        if((error = ak_bckey_ofb(&key, addr2, data2, target_file.mmaped_size, iv, sizeof(iv))) != ak_error_ok){
            aktool_error(("problem with encrypt_ofd %d"));
            printf("cod of error: %d\n", error);
            errcount++;
            return EXIT_FAILURE;
        } else{
            work_of_encrypt = 1;
        }
    }
    if ((strcmp (encrypt_mode, "cfb") == 0)){
        int error;
        if((error = ak_bckey_encrypt_cfb(&key, addr2, data2, target_file.mmaped_size, iv, sizeof(iv))) != ak_error_ok){
            aktool_error(("problem with encrypt_cfb %d"));
            printf("cod of error: %d\n", error);
            errcount++;
            return EXIT_FAILURE;
        } else{
            work_of_encrypt = 1;
        }
    }
    if (work_of_encrypt == 0){
        aktool_error(_("Problem with encryption of file"));
        errcount++;
        return EXIT_FAILURE;
    }




    struct file write_file;
    if (ak_file_create_to_write( &write_file, file2) == ak_error_access_file){
        aktool_error(_("problem create file to write"));
        errcount++;
        return EXIT_FAILURE;
    }
    if (ak_file_write(&write_file, data2, size) == ak_error_write_data){
        aktool_error(_("problem create file to write"));
        errcount++;
        return EXIT_FAILURE;
    }
    free(data2);
    ak_file_close( &write_file);
    ak_file_unmap( &target_file);
    ak_file_close( &target_file);
    ak_file_unmap( &key_file );
    ak_file_close( &key_file );

    return exitcode;
}






int cipher_ss(int argc, tchar *argv[]){
    int next_option = 0, exitcode = EXIT_FAILURE;
    enum {do_nothing, er_rt} work = do_nothing;

    static char key_file[1024];
    static char algorithm[512];
    static char encrypt_mode[512];
    static char target[1024];
    static char out[1024];
    static char sync_message[1024];
    static char buff[512];
    int chek = 0;
    int in_file = 0;
    int out_file = 0;




    const struct option long_options[] = {
            { "bckey",                 1, NULL,  'b' },
            { "algorithm_of_encrypt",  1, NULL,  'a' },
            { "encrypt_mode",          1, NULL,  'e' },
            { "sync_message",          2, NULL,  'm' },
            { "target",                1, NULL,  't' },
            { "out",                   1, NULL,  'o' },
            { "in_file",               1, NULL,  203 },
            { "out_file",              1, NULL,  205 },
            aktool_common_functions_definition

    };

    do {
        next_option = getopt_long(argc, argv, "hb:a:e:t:o:m:203:205:", long_options, NULL);
        switch (next_option){
            aktool_common_functions_run(aktool_cip_help);
            case 'b':
                work = er_rt;
                realpath( optarg , key_file);
                break;

            case 'a':
                work =er_rt;
                strcpy(algorithm, optarg);
                break;

            case 'e':
                work =er_rt;
                strcpy(encrypt_mode, optarg);
                break;

            case 't':
                work =er_rt;
                realpath( optarg , target);
                break;

            case 'o':
                work =er_rt;
                realpath( optarg , out);
                break;

            case 'm':
                work =er_rt;
                chek = 1;
                realpath( optarg , sync_message);
                break;
            case 203:
                in_file = atoi(optarg);
                break;
            case 205:
                out_file = atoi(optarg);
                break;
        }
    } while( next_option != -1 );
    if( work == do_nothing ) return aktool_cip_help();

//    if( !aktool_create_libakrypt( )) return EXIT_FAILURE;




    if (chek == 0){
        realpath( "sync_message.iv" , sync_message);
        generation_of_sync_message(sync_message);
    }

    exitcode = cipher_encryption (key_file, algorithm,encrypt_mode,target, out, sync_message, in_file, out_file);






    /* завершаем работу и выходим */
    aktool_destroy_libakrypt();
    return exitcode;
}
