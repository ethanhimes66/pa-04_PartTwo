/*-------------------------------------------------------------------------------

FILE:   dispatcher.c

Written By: 
     1- Dr. Mohamed Aboutabl
Submitted on: 
-------------------------------------------------------------------------------*/

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/wait.h>
#include <time.h>

#include "wrappers.h"

#define   READ_END	0
#define   WRITE_END	1
#define   STDIN  0
#define   STDOUT 1

//--------------------------------------------------------------------------
int main( int argc , char *argv[] )
{
    pid_t  amalPID , basimPID , KDCPID ; 
    int    AtoB[2] , BtoA[2], AtoKDC[2], KDCtoA[2];;  // Amal, Basim, & KDC pipes
    char   arg1[20] , arg2[20], arg3[20] , arg4[20] ;
    
    Pipe( AtoKDC ) ;  // create pipe for Amal-to-KDC
    Pipe( KDCtoA ) ;  // create pipe for KDC-to-Amal
    Pipe( AtoB ) ;  // create pipe for Amal-to-Basim
    Pipe( BtoA ) ;  // create pipe for Basim-to-Amal


    printf("\nDispatcher started ... ") ;
    char myUserName[30] ;
    getlogin_r ( myUserName , 30 ) ;
    time_t  now;
    time( &now ) ;
    fprintf( stdout , "Logged in as user '%s' on %s\n\n" , myUserName ,  ctime( &now)  ) ;
    
    printf("Dispatcher started and created these pipes\n") ;
    printf("1) Amal-to-KDC   protocol pipe: read=%d  write=%d\n", AtoKDC[ READ_END ] , AtoKDC[ WRITE_END ] ) ;
    printf("2) KDC-to-Amal   protocol pipe: read=%d  write=%d\n", KDCtoA[ READ_END ] , KDCtoA[ WRITE_END ] ) ;
    printf("3) Amal-to-Basim protocol pipe: read=%d  write=%d\n", AtoB[ READ_END ] , AtoB[ WRITE_END ] ) ;
    printf("4) Basim-to-Amal protocol pipe: read=%d  write=%d\n", BtoA[ READ_END ] , BtoA[ WRITE_END ] ) ;
    printf("\n");


    // Create all three child processes:
    amalPID = Fork() ;
    if ( amalPID == 0 )
    {    
        // This is the Amal process.
        // Amal will not use these ends of the pipes, decrement their 'Ref Count'
        close( AtoB[ READ_END ] ) ;
        close( BtoA[ WRITE_END ] ) ;
        close( AtoKDC [ READ_END ] ) ;
        close( KDCtoA [ WRITE_END ] ) ;
        
        // Prepare the file descriptors as args to Amal
        snprintf( arg1 , 20 , "%d" , KDCtoA[ READ_END ] ) ;
        snprintf( arg2 , 20 , "%d" , AtoKDC[ WRITE_END ] ) ;
        snprintf( arg3 , 20 , "%d" , BtoA[ READ_END ] ) ;
        snprintf( arg4 , 20 , "%d" , AtoB[ WRITE_END ] ) ;
        
        // Now, Start Amal
        char * cmnd = "./amal/amal" ;
        execlp( cmnd , "Amal" , arg1 , arg2 , arg3, arg4, NULL );

        // the above execlp() only returns if an error occurs
        perror("ERROR starting Amal" );
        exit(-1) ;      
    } 
    else
    {    // This is still the Dispatcher process 
        basimPID = Fork() ;
        if ( basimPID == 0 )
        {  
            // This is the Basim process
            // Basim will not use these ends of the pipes, decrement their 'count'
            close( AtoB[ WRITE_END ] ) ;
            close( BtoA[ READ_END ] ) ;
            close( AtoKDC [ READ_END ] ) ;
            close( KDCtoA [ WRITE_END ] ) ;
            close( AtoKDC [ WRITE_END ] ) ;
            close( KDCtoA [ READ_END ] ) ;
            
            // Prepare the file descriptors as args to Basim
            snprintf( arg1 , 20 , "%d" , AtoB[ READ_END ] ) ;
            snprintf( arg2 , 20 , "%d" , BtoA[ WRITE_END ] ) ;

            char * cmnd = "./basim/basim" ;
            execlp( cmnd , "Basim" , arg1 , arg2 , NULL );

            // the above execlp() only returns if an error occurs
            perror("ERROR starting Basim" ) ;
            exit(-1) ;
        }
        else
        {   
            KDCPID = Fork() ;
            if ( KDCPID == 0 )
            {  
                // This is the Basim process
                // Basim will not use these ends of the pipes, decrement their 'count'
                close( AtoB[ WRITE_END ] ) ;
                close( BtoA[ READ_END ] ) ;
                close( AtoB [ READ_END ] ) ;
                close( BtoA [ WRITE_END ] ) ;
                close( AtoKDC [ WRITE_END ] ) ;
                close( KDCtoA [ READ_END ] ) ;
                
                // Prepare the file descriptors as args to Basim
                snprintf( arg1 , 20 , "%d" , AtoKDC[ READ_END ] ) ;
                snprintf( arg2 , 20 , "%d" , KDCtoA[ WRITE_END ] ) ;

                char * cmnd = "./kdc/kdc" ;
                execlp( cmnd , "KDC" , arg1 , arg2 , NULL );

                // the above execlp() only returns if an error occurs
                perror("ERROR starting the KDC" ) ;
                exit(-1) ;
            }
            else {
                // This is still the parent Dispatcher  process
                // close all ends of the pipes so that their 'count' is decremented
                close( AtoB[ WRITE_END ] ); 
                close( AtoB[ READ_END  ]  );   
                close( BtoA[ WRITE_END ] ); 
                close( BtoA[ READ_END  ]  );
                close( AtoKDC[ WRITE_END ] ); 
                close( AtoKDC[ READ_END  ]  );   
                close( KDCtoA[ WRITE_END ] ); 
                close( KDCtoA[ READ_END  ]  );      

                printf("\nDispatcher is now waiting for Amal to terminate\n") ;
                int  exitStatus ;
                waitpid( amalPID , &exitStatus , 0 ) ;
                // printf("\n\tAmal terminated ... "  ) ;
                // if (  WIFEXITED( exitStatus ) )
                //         printf(" with status =%d\n" , WEXITSTATUS(exitStatus ) ) ;

                printf("\nDispatcher is now waiting for Basim to terminate\n") ;
                waitpid( basimPID , &exitStatus , 0 ) ;
                // printf("\n\tBasim terminated ... " ) ;
                // if (  WIFEXITED( exitStatus ) )
                //         printf(" with status =%d\n" , WEXITSTATUS(exitStatus ) ) ;

                printf("\nDispatcher is now waiting for the KDC to terminate\n") ;
                waitpid( KDCPID , &exitStatus , 0 ) ;
                // printf("\n\tKDC terminated ... " ) ;
                // if (  WIFEXITED( exitStatus ) )
                //         printf(" with status =%d\n" , WEXITSTATUS(exitStatus ) ) ;

                printf("\nDispatcher process has terminated\n\n");
            }
        }
    }  
}

