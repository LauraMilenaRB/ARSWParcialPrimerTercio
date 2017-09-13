/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package edu.eci.arsw.blacklistvalidator;

import edu.eci.arsw.spamkeywordsdatasource.HostBlacklistsDataSourceFacade;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 *
 * @author hcadavid
 */
public class HostBlackListsValidator {

    private static final int BLACK_LIST_ALARM_COUNT=5;
    private Thr hilos[];
    public static AtomicInteger ocurrencesCount=new AtomicInteger(0);
    public static AtomicInteger checkedListsCount=new AtomicInteger(0);
    public static AtomicInteger numhilos=new AtomicInteger(0);
    public static ConcurrentLinkedQueue<Integer> blackListOcurrences=new ConcurrentLinkedQueue<>();
     
    /**
     * Check the given host's IP address in all the available black lists,
     * and report it as NOT Trustworthy when such IP was reported in at least
     * BLACK_LIST_ALARM_COUNT lists, or as Trustworthy in any other case.
     * The search is not exhaustive: When the number of occurrences is equal to
     * BLACK_LIST_ALARM_COUNT, the search is finished, the host reported as
     * NOT Trustworthy, and the list of the five blacklists returned.
     * @param ipaddress suspicious host's IP address.
     * @return  Blacklists numbers where the given host's IP address was found.
     */
    public ConcurrentLinkedQueue checkHost(String ipaddress,int N){
        HostBlacklistsDataSourceFacade skds=HostBlacklistsDataSourceFacade.getInstance();
        int ntotal=skds.getRegisteredServersCount()/N;
        int intervalob=ntotal;
        int intervaloa=0;
        hilos= new Thr[N];
        for (int i =0; i<N;i++){
            hilos[i]=new Thr(intervaloa,intervalob,ipaddress,skds,N);
            hilos[i].start();
            intervaloa+=ntotal;
            intervalob+=ntotal;
        
        }
        synchronized(blackListOcurrences){
            try {
                blackListOcurrences.wait();
            } catch (InterruptedException ex) {
                Logger.getLogger(HostBlackListsValidator.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
        
        if (ocurrencesCount.get()>=BLACK_LIST_ALARM_COUNT){
            skds.reportAsNotTrustworthy(ipaddress);
        }
        else{
            skds.reportAsTrustworthy(ipaddress);
        }                
        
        LOG.log(Level.INFO, "Checked Black Lists:{0} of {1}", new Object[]{checkedListsCount, skds.getRegisteredServersCount()});
        
        return  blackListOcurrences;
    }
    
    
    private static final Logger LOG = Logger.getLogger(HostBlackListsValidator.class.getName());
    
    
    public static final int getBLACK_LIST_ALARM_COUNT(){
        return BLACK_LIST_ALARM_COUNT;
    }
    
}
