/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package edu.eci.arsw.blacklistvalidator;

import edu.eci.arsw.spamkeywordsdatasource.HostBlacklistsDataSourceFacade;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedDeque;

/**
 *
 * @author 2106340
 */
public class Thr extends Thread {
    HostBlacklistsDataSourceFacade skds;
    String ip="";
    int a,b=0;
    int n=0;
    public Thr(int a, int b,String ipaddress,HostBlacklistsDataSourceFacade sdk,int n) {
        this.ip=ipaddress;
        this.a=a;
        this.b=b;
        this.skds=sdk;
        this.n=n;
    }
    
    public void run(){
        for (int i = a; i < b && HostBlackListsValidator.ocurrencesCount.get() < HostBlackListsValidator.getBLACK_LIST_ALARM_COUNT(); i++) {
            HostBlackListsValidator.checkedListsCount.getAndAdd(1);
            if (skds.isInBlackListServer(i, ip)) {
                HostBlackListsValidator.blackListOcurrences.add(i);
                HostBlackListsValidator.ocurrencesCount.addAndGet(1);
            }
        }
        if(HostBlackListsValidator.numhilos.get()<n-1 && HostBlackListsValidator.ocurrencesCount.get()!=HostBlackListsValidator.getBLACK_LIST_ALARM_COUNT()){
            HostBlackListsValidator.numhilos.addAndGet(1);
        }else{
            synchronized (HostBlackListsValidator.blackListOcurrences) {
                HostBlackListsValidator.blackListOcurrences.notify();
            }
        }
        
    }
    
}
    

