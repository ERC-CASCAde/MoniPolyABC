
import org.apache.milagro.amcl.BLS48.ECP;
import org.apache.milagro.amcl.BLS48.ECP8;
import org.apache.milagro.amcl.BLS48.ROM;
import org.apache.milagro.amcl.BLS48.BIG;
/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/**
 * The project is supported by the European Research Council (ERC) under grant agreement no. 716980.
 * @author nsyt1
 */
public class ABCpk {
    private final ECP a0,b,c;
    private final ECP[] a;
    private final ECP8 g2;
    private final ECP8 g2x;
    private final ECP8[] X;
    
    public ABCpk(ECP a0,ECP b,ECP c,ECP[] a,ECP8 g2,ECP8 g2x, ECP8[] X){
        this.a0= a0;
        this.a = a;
        this.b = b;
        this.c = c;
        this.g2 = g2;
        this.g2x = g2x;
        this.X = X;
    }
    
    public ECP get_a0(){
        return a0;
    }
      
    public ECP get_b(){
        return b;
    }
    
    public ECP[] get_a(){
        return a;
    }
    
    public ECP get_c(){
        return c;
    }
    
    public ECP8 get_g2(){
        return g2;
    }
    
    public ECP8 get_g2x(){
        return g2x;
    }
    
    public ECP8[] get_X(){
        return X;
    }
    
    public String toString(){
        StringBuilder str=new StringBuilder();
        str.append("BLS48 Curve\n");
        str.append("order: "+new BIG(ROM.CURVE_Order)+"\n");
        str.append("|order|: "+new BIG(ROM.CURVE_Order).nbits()+"bits\n");
        str.append("p: "+new BIG(ROM.Modulus)+"\n");
        str.append("|p|: "+new BIG(ROM.Modulus).nbits()+"bits\n");
        str.append("a_0: "+a0.toString()+"\n");
        str.append("b: "+b.toString()+"\n");
        str.append("c: "+c.toString()+"\n");
        str.append("g2: "+g2.toString()+"\n");
        str.append("X: "+g2x.toString()+"\n");
        for(int i=0;i<a.length;i++){
            str.append("a["+i+"]: "+a[i].toString()+"\n");
        }
        for(int i=0;i<X.length;i++){
            str.append("X["+i+"]: "+X[i].toString()+"\n");
        }
        
        return str.toString();
    }    
}
