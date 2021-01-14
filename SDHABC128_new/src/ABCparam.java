/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/**
 *
 * @author nsyt1
 */
public class ABCparam {
    private final ABCpk pk;
    private final ABCsk sk;
    
    public ABCparam(ABCpk pk, ABCsk sk){
        this.pk = pk;
        this.sk = sk;
    }
    
    public ABCpk getPK(){
        return pk;
    }
    
    public ABCsk getSK(){
        return sk;
    }
}
