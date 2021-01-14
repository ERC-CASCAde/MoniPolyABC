
import org.apache.milagro.amcl.BLS48.BIG;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/**
 *
 * @author nsyt1
 */
public class ABCsk {
    private final BIG x;
    private final BIG xprime;
    
    public ABCsk(BIG x, BIG xprime){
        this.x = x;
        this.xprime = xprime;
    }
    
    public BIG get_x(){
        return x;
    }
    
    public BIG get_xprime(){
        return xprime;
    }
    
    public String toString(){
        StringBuilder str = new StringBuilder();
        str.append("x: "+x.toString()+"\n");
        str.append("x': "+xprime.toString()+"\n");
        
        return str.toString();
    }
    
}
