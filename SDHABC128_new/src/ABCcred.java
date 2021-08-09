
import org.apache.milagro.amcl.BLS461.BIG;
import org.apache.milagro.amcl.BLS461.ECP;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/**
 * The project is supported by the European Research Council (ERC) under grant agreement no. 716980.
 * @author nsyt1
 */
public class ABCcred {
    private final BIG t,s;
    private final ECP v;
    private final BIG[] alphas;//, alphasNoO;
    private final String[] A;
    
    public ABCcred(BIG t, BIG s, ECP v, String[] A, BIG[] alphas){//, BIG[] alphasNoO){
        this.t = t;
        this.s = s;
        this.v = v;      
        this.A = A;
        this.alphas = alphas;
        //this.alphasNoO = alphasNoO;
    }
    
    public BIG get_t(){
        return t;
    }
    
    public BIG get_s(){
        return s;
    }
    
    public ECP get_v(){
        return v;
    }
    
    public BIG[] get_alphas(){
        return alphas;
    }

    public String[] get_A(){
        return A;
    }
}
