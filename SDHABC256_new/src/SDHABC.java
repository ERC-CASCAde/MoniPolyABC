
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.milagro.amcl.BLS48.*;
import org.apache.milagro.amcl.RAND;

/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

/**
 * The project is supported by the European Research Council (ERC) under grant agreement no. 716980.
 * @author nsyt1
 */
public class SDHABC {   
    /**
     * Generate ABC public and private keys.
     * @param attrSize maximum size of attribute supported.
     * 
     * @return ABC parameter
     */
    public ABCparam Setup(int attrSize){
        RAND RNG = new RAND();
        ECP[] a=new ECP[attrSize];
        ECP8[] X=new ECP8[attrSize];
        ECP a0 = ECP.generator();
        ECP8 g2 = ECP8.generator();        
        
        BIG q=new BIG(ROM.CURVE_Order);
	
        SecureRandom rand = new SecureRandom();
        RNG.clean();
	RNG.seed(100,rand.generateSeed(100));        
        
        BIG x=BIG.randomnum(q,RNG);
        ECP8 g2x = PAIR256.G2mul(g2, x);
        
        BIG xprime=BIG.randomnum(q,RNG);
        BIG _1 = new BIG();
        _1.one();
        
        BIG j = new BIG();        
        j.zero();
        
        for(int i=0;i<attrSize;i++){            
            a[i] = PAIR256.G1mul(a0, xprime.powmod(j, q));
            X[i] = PAIR256.G2mul(g2, xprime.powmod(j, q));
            j.add(_1);
        }
        
        ECP b = PAIR256.G1mul(a0,BIG.randomnum(q,RNG));
        ECP c = PAIR256.G1mul(a0,BIG.randomnum(q,RNG));
        ABCpk pk = new ABCpk(a0,b,c,a,g2,g2x,X);
        ABCsk sk = new ABCsk(x,xprime);
	//s.toBytes(S);
	//G.toBytes(W);
        
        /*//simple operation benchmark
        long start, total1=0, total2=0, total3=0, total4=0, totalrsa=0;       
        FP48 pair = PAIR256.fexp(PAIR256.ate(g2,a0));
         
        //for RSA
        BigInteger qq,Q,pp,P,N,R;
        do{
                qq = new BigInteger(15360/2-1, 16, rand);
                pp = new BigInteger(15360/2-1, 16, rand);
                Q=qq.multiply(BigInteger.valueOf(2)).add(BigInteger.ONE);
                P=pp.multiply(BigInteger.valueOf(2)).add(BigInteger.ONE);
                N = P.multiply(Q);
        }while(!qq.isProbablePrime(16) || !pp.isProbablePrime(16) || !Q.isProbablePrime(16) || !P.isProbablePrime(16) || N.bitLength()<15359);
        R=new BigInteger(rand.generateSeed(15360/8)).mod(N);
        //end RSA
         
        for(int i=0;i<100;i++){
            BIG num = BIG.randomnum(q,RNG); 
            BigInteger num1 = toBigInteger(num);
             
            start = System.nanoTime();
            a0=PAIR256.G1mul(a0, num);
            total1 += System.nanoTime() - start;
             
            start = System.nanoTime();
            PAIR256.G2mul(g2, num);
            total2 += System.nanoTime() - start;
             
            start = System.nanoTime();
            pair.pow(num);
            total3 += System.nanoTime() - start;           
             
            start = System.nanoTime();
            PAIR256.fexp(PAIR256.ate(g2,a0));
            total4 += System.nanoTime() - start;
             
            start = System.nanoTime();
            R.modPow(num1, N);
            totalrsa += System.nanoTime() - start;
        }
        System.out.println("G1 scalar multiplication takes  : "+java.util.concurrent.TimeUnit.MILLISECONDS.convert(total1/100, java.util.concurrent.TimeUnit.NANOSECONDS)+"ms");
        System.out.println("G2 scalar multiplication takes  : "+java.util.concurrent.TimeUnit.MILLISECONDS.convert(total2/100, java.util.concurrent.TimeUnit.NANOSECONDS)+"ms");
        System.out.println("GT exponentiation takes         : "+java.util.concurrent.TimeUnit.MILLISECONDS.convert(total3/100, java.util.concurrent.TimeUnit.NANOSECONDS)+"ms");
        System.out.println("Pairing takes                   : "+java.util.concurrent.TimeUnit.MILLISECONDS.convert(total4/100, java.util.concurrent.TimeUnit.NANOSECONDS)+"ms");
        System.out.println("RSA modular exponentiation takes: "+java.util.concurrent.TimeUnit.MILLISECONDS.convert(totalrsa/100, java.util.concurrent.TimeUnit.NANOSECONDS)+"ms");
        //end*/
        
        return new ABCparam(pk, sk);
    }
    
    /**
     * ABC Issuing protocol. It contains precomputation MPEncode(A) and MPEncode(A-o) where A={m_1,...,m_n-1,o}.
     * 
     * @param pk ABC public key.
     * @param A Attribute set
     * @param sk ABC secret key.
     * 
     * @throws Exception if |A| is greater than supported attribute size it fails or the protocol fails.
     * 
     * @return an ABC credential
     */
    public ABCcred Issuing(ABCpk pk, String[] A, ABCsk sk) throws Exception{
        
        if(A.length>pk.get_a().length-1){
            throw new Exception("Maximum supported attribute size is "+(pk.get_a().length-1)+" only.");
        }
        
        RAND RNG = new RAND();
        BIG[] attr = new BIG[A.length];
        BIG[] alphas = new BIG[A.length+1];
        BIG order = new BIG(ROM.CURVE_Order);
        
        try {
            SecureRandom rand = new SecureRandom();
            RNG.clean();
            RNG.seed(100,rand.generateSeed(100));
        
            MessageDigest H = MessageDigest.getInstance("SHA-512");
                        
            for(int i=0;i<attr.length;i++){                
                byte[] temp = H.digest(A[i].getBytes());
                byte[] hash = new byte[CONFIG_BIG.MODBYTES];
                for(int j=0;j<hash.length;j++){
                    if(j<temp.length)
                        hash[j]=temp[j];
                    else
                        hash[j]=0x00;
                }
                attr[i]= BIG.fromBytes(hash);
                attr[i].mod(order);
            }
            alphas = MPEncode(attr, order);
            
            //user chooses random tilde{s,alpha_0,...\alpha_n}
            BIG s1 = BIG.randomnum(order,RNG);
            BIG tildeS = BIG.randomnum(order,RNG);
            BIG[] tildeA = new BIG[alphas.length];
            
            //calculate C,R
            ECP C = PAIR256.G1mul(pk.get_b(), s1);
            ECP R = PAIR256.G1mul(pk.get_b(), tildeS);
            
            for(int i=0;i<tildeA.length;i++){
                C.add(PAIR256.G1mul(pk.get_a()[i], alphas[i]));
                
                tildeA[i] = BIG.randomnum(order,RNG);
                R.add(PAIR256.G1mul(pk.get_a()[i], tildeA[i]));
            }
            //send C,R to issuer
            
            //issuer gives challenge
            BIG e = BIG.randomnum(order,RNG);
            
            //send response to issuer
            tildeS.add(BIG.modmul(e, s1, order));
            tildeS.mod(order);
            for(int i=0;i<tildeA.length;i++){
                tildeA[i].add(BIG.modmul(e, alphas[i], order));
                tildeA[i].mod(order);
            }
            
            //issuer verify
            ECP _C = PAIR256.G1mul(pk.get_b(), tildeS);
            for(int i=0;i<tildeA.length;i++){
                _C.add(PAIR256.G1mul(pk.get_a()[i], tildeA[i]));
            }
            R.add(PAIR256.G1mul(C, e));
            
            if(_C.equals(R)){
           
                BIG t = BIG.randomnum(order,RNG);
                BIG s2 = BIG.randomnum(order,RNG);
                C.add(PAIR256.G1mul(pk.get_b(), s2));
                C.add(pk.get_c());
                BIG _t = new BIG(t);
                //_t.copy(t);
                _t.add(sk.get_x());
                _t.invmodp(order);
                ECP v = PAIR256.G1mul(C,_t);
                
                //received credential (t,s2,v)
                s1.add(s2);     
                s1.mod(order);
                
                //verify if this is a valid credential
                ECP temp = PAIR256.G1mul(v,t);
                temp.neg();
                
                temp.add(pk.get_c());
                temp.add(PAIR256.G1mul(pk.get_b(),s1));
                
                for(int i=0;i<alphas.length;i++){
                    temp.add(PAIR256.G1mul(pk.get_a()[i],alphas[i]));
                }
                
                FP48 left=PAIR256.fexp(PAIR256.ate(pk.get_g2x(),v));
                
                FP48 right=PAIR256.fexp(PAIR256.ate(pk.get_g2(),temp));
                
                
		if (left.equals(right)){
                    return new ABCcred(t,s1,v,A,alphas);
                }
                else{
                    return null;
                }
            }
            else{
                return null;
            }
        
        } catch (NoSuchAlgorithmException ex) {
            Logger.getLogger(SDHABC.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }
    
    /**
     * ABC Proof of Possession protocol. It precomputes MPEncode(A) on attribute set A.
     * 
     * @param pk ABC public key.
     * @param cred ABC credential.
     * 
     * @return true if the credential is legit corresponding to hidden attributes A; false otherwise.
     */
    public boolean proofOfPossession(ABCpk pk, ABCcred cred){
        try{
        MessageDigest H = MessageDigest.getInstance("SHA-512");
        RAND RNG = new RAND();
        BIG r,y,_r,_y,_ty,_s,_o0,_o1;
        //BIG[] _alpha = new BIG[cred.get_alphas().length];        
        BIG order = new BIG(ROM.CURVE_Order);
        
        SecureRandom rand = new SecureRandom();
        RNG.clean();
	RNG.seed(100,rand.generateSeed(100));
        
        //prover sends commitment and witnesses        
        r = BIG.randomnum(order,RNG);
        y = BIG.randomnum(order,RNG);
        BIG yinv=new BIG(y);
        //yinv.copy(y);
        yinv.invmodp(order);
        _r = BIG.randomnum(order,RNG);
        _y = BIG.randomnum(order,RNG);
        _ty = BIG.randomnum(order,RNG);
        _s = BIG.randomnum(order,RNG);
        _o0 = BIG.randomnum(order,RNG);
        _o1 = BIG.randomnum(order,RNG);
        
        ECP V1 = PAIR256.G1mul(cred.get_v(), BIG.modmul(BIG.modmul(r, r, order), yinv, order));
        ECP V2 = PAIR256.G1mul(V1, _y);
        ECP Y1 = PAIR256.G1mul(V1, _ty);
        ECP8 Y2 = PAIR256.G2mul(pk.get_X()[0], _o0);        
        Y2.add(PAIR256.G2mul(pk.get_X()[1], _o1));
        Y1.add(PAIR256.G1mul(pk.get_c(), _r));
        Y1.add(PAIR256.G1mul(pk.get_b(), _s));
        
        byte[] temph = H.digest(cred.get_A()[cred.get_A().length-1].getBytes());
        byte[] hash = new byte[CONFIG_BIG.MODBYTES];
        for(int j=0;j<hash.length;j++){
            if(j<temph.length)
                hash[j]=temph[j];
            else
                hash[j]=0x00;
        }
        BIG o0 = BIG.fromBytes(hash);
        BIG[] w = new BIG[1];        
        w[0] = new BIG(o0);
        w = syntheticDivision(cred.get_alphas(),MPEncode(w,order))[0];
        
        ECP W = new ECP();
        for(int i=0;i<w.length;i++){            
            W.add(PAIR256.G1mul(pk.get_a()[i], w[i]));
        }
        W = PAIR256.G1mul(W, r);
        
        //verifier replies a challenge
        BIG e = BIG.randomnum(order,RNG);
        
        //prover sends response
        _r.add(BIG.modmul(e, BIG.modmul(r, r, order), order)); 
        _r.mod(order);
        _y.add(BIG.modmul(e, y, order));        
        _y.mod(order);
        _ty.sub(BIG.modmul(e, BIG.modmul(cred.get_t(), y, order), order));        
        _ty.mod(order);
        _s.add(BIG.modmul(e, BIG.modmul(cred.get_s(),BIG.modmul(r, r, order),order), order));
        _s.mod(order);
        _o1.add(BIG.modmul(e, r, order)); 
        _o1.mod(order);
        
        
        o0.mod(order);
        o0 = BIG.modmul(r, o0, order);
        _o0.add(BIG.modmul(e, o0, order)); 
        _o0.mod(order);        
        //for(int i=0;i<_alpha.length;i++){
        //    _alpha[i].add(BIG.modmul(e, BIG.modmul(cred.get_alphas()[i],r,order), order));
        //    _alpha[i].mod(order);
        //}
        
        //verifier checks
        FP48[] ll=PAIR256.initmp();
        ECP8 temp2 = PAIR256.G2mul(pk.get_X()[0],_o0);
        temp2.add(PAIR256.G2mul(pk.get_X()[1],_o1));
        temp2.sub(Y2);
        PAIR256.another(ll, temp2, W);
        
        ECP temp = PAIR256.G1mul(V1, _ty);
        temp.add(PAIR256.G1mul(pk.get_c(), _r));
        temp.add(PAIR256.G1mul(pk.get_b(), _s));
        //for(int i=0;i<_alpha.length;i++){
        //    temp.add(PAIR.G1mul(pk.get_a()[i], _alpha[i]));            
        //}
        temp.sub(Y1);
        //temp.add(PAIR.G1mul(W, e));
        PAIR256.another(ll, pk.get_g2(), temp);
        //FP12 left2 = PAIR.fexp(PAIR.ate(pk.get_g2(), temp));
        
        //FP12 right1 = PAIR.fexp(PAIR.ate(pk.get_g2(), Y));
        
        temp = PAIR256.G1mul(V1, _y);
        temp.sub(V2);
        
        //FP12 right2 = PAIR.fexp(PAIR.ate(pk.get_g2x(), temp2));
        
        //right1.mul(right2);
        
        //FP12[] rr=PAIR.initmp();
	//PAIR.another(rr,pk.get_g2(), Y);
	
	FP48 right=PAIR256.fexp(PAIR256.ate(pk.get_g2x(), temp));
        
        if(PAIR256.fexp(PAIR256.miller(ll)).equals(right))            
            return true;
        else
            return false;
        }
        catch(Exception e){
            Logger.getLogger(SDHABC.class.getName()).log(Level.SEVERE, null, e);
        }
        
        return false;
    }    
    
    /**
     * ABC AND Proof protocol.
     * 
     * @param pk ABC public key.
     * @param cred ABC credential.
     * @param Aprime query attribute set.
     * 
     * @throws Exception if the searching for intersecting attributes fails or the protocol fails.
     * 
     * @return true if A' is subset or equal to A, false otherwise.
     */
    public boolean proofOfAND(ABCpk pk, ABCcred cred, String[] Aprime) throws Exception{
        try{
        MessageDigest H = MessageDigest.getInstance("SHA-512");
        RAND RNG = new RAND();
        BIG r,y,_r,_y,_ty,_s;        
        BIG order = new BIG(ROM.CURVE_Order);
        
        BIG[] m;
        
        //new intersection function        
        //if threshold doesn't met, exception thrown
        //so, we don't need to perform a check anymore
        ArrayList<String>[] result = findSame(Aprime.length,cred.get_A(),Aprime);                
        
        if(Aprime.length<cred.get_A().length){
            m = new BIG[result[0].size()];
            for(int i=0;i<m.length;i++){
                 byte[] temp = H.digest(result[0].get(i).getBytes());
                byte[] hash = new byte[CONFIG_BIG.MODBYTES];
                for(int j=0;j<hash.length;j++){
                    if(j<temp.length)
                        hash[j]=temp[j];
                    else
                        hash[j]=0x00;
                }
                m[i] = BIG.fromBytes(hash);
                m[i].mod(order);
            }
            //encode them
            m = syntheticDivision(cred.get_alphas(),MPEncode(m, order))[0];
        }
        else{
            m = new BIG[1];
            m[0] = new BIG();
            m[0].one();
        }
        
        
        SecureRandom rand = new SecureRandom();
        RNG.clean();
	RNG.seed(100,rand.generateSeed(100));
        
        //BIG[] _beta = new BIG[beta.length];
        
        r = BIG.randomnum(order,RNG);
        y = BIG.randomnum(order,RNG);
        BIG yinv=new BIG(y);
        yinv.invmodp(order);
        _r = BIG.randomnum(order,RNG);
        _y = BIG.randomnum(order,RNG);
        _ty = BIG.randomnum(order,RNG);
        _s = BIG.randomnum(order,RNG);
        
        ECP Vprime = PAIR256.G1mul(cred.get_v(), BIG.modmul(r, yinv, order));
        ECP V = PAIR256.G1mul(Vprime, _y);
        
        ECP M = PAIR256.G1mul(pk.get_a0(), m[0]);
        for(int i=1;i<m.length;i++){
            M.add(PAIR256.G1mul(pk.get_a()[i], m[i]));
        }
        M = PAIR256.G1mul(M, r);
        
        ECP Y = PAIR256.G1mul(Vprime, _ty);
        Y.add(PAIR256.G1mul(pk.get_c(), _r));
        Y.add(PAIR256.G1mul(pk.get_b(), _s));        
        
        //verifier replies a challenge
        BIG e = BIG.randomnum(order,RNG);        
      
        //prover sends response
        //\hat{r}=\tilde{r}+er
        _r.add(BIG.modmul(e, r, order));
        _r.mod(order);        
        //\hat{y}=\tilde{y}+ey
        _y.add(BIG.modmul(e, y, order));        
        _y.mod(order);
        //\hat{t_y}=\tilde{t_y}-ety
        _ty.sub(BIG.modmul(e, BIG.modmul(cred.get_t(), y, order), order));  
        _ty.mod(order);
        //\hat{s}=\tilde{s}+esr
        _s.add(BIG.modmul(e, BIG.modmul(cred.get_s(),r,order), order));
        _s.mod(order);
                
        //verifier checks        
        //new checking, only 3 pairings
        FP48[] ll=PAIR256.initmp();	
        
        BIG[] z = new BIG[Aprime.length];
        for(int i=0;i<Aprime.length;i++){
            byte[] temp = H.digest(Aprime[i].getBytes());
            byte[] hash = new byte[CONFIG_BIG.MODBYTES];
                for(int j=0;j<hash.length;j++){
                    if(j<temp.length)
                        hash[j]=temp[j];
                    else
                        hash[j]=0x00;
                }
            z[i] = BIG.fromBytes(hash);
            z[i].mod(order);
        }
        z = MPEncode(z, order);
        
        ECP8 temp2 = PAIR256.G2mul(pk.get_g2(), z[0]);
        for(int i=1;i<z.length;i++){
            temp2.add(PAIR256.G2mul(pk.get_X()[i], z[i]));            
        }
        PAIR256.another(ll,temp2, PAIR256.G1mul(M, e));
        
        
        ECP temp=PAIR256.G1mul(pk.get_b(), _s);
        temp.add(PAIR256.G1mul(pk.get_c(), _r));
        temp.add(PAIR256.G1mul(Vprime, _ty));        
        temp.sub(Y);
        
	PAIR256.another(ll,pk.get_g2(), temp);
	FP48 left=PAIR256.fexp(PAIR256.miller(ll));
                       
        
        temp = PAIR256.G1mul(Vprime, _y);
        temp.sub(V);
       
        
	FP48 right=PAIR256.fexp(PAIR256.ate(pk.get_g2x(), temp));
        
                
        if(left.equals(right)){
            //System.out.println("left: "+left);
            //System.out.println("right: "+right);
            return true;
        }
        else{
            //System.out.println("left: "+left);
            //System.out.println("right: "+right);
            return false;
        }
        }
        catch(NoSuchAlgorithmException e){
            Logger.getLogger(SDHABC.class.getName()).log(Level.SEVERE, null, e);
        } catch (Exception ex) {
            Logger.getLogger(SDHABC.class.getName()).log(Level.SEVERE, null, ex);
            throw new Exception("AND proof: "+ex.getMessage());            
        }
        
        return false;
    }
    
    /**
     * ABC ANY Proof protocol.
     * 
     * @param pk ABC public key.
     * @param cred ABC credential.
     * @param threshold the threshold \ell which is at most |A'| and at most |A|.
     * @param Aprime query attribute set.
     * 
     * @throws Exception if the searching for intersecting attributes fails or the protocol fails.
     * 
     * @return true if A' intersected A for at least threshold-many attributes, false otherwise.
     */
    public boolean proofOfANY(ABCpk pk, ABCcred cred, int threshold, String[] Aprime) throws Exception{
        try{
        MessageDigest H = MessageDigest.getInstance("SHA-512");
        RAND RNG = new RAND();
        BIG r,y,_r,_y,_ty,_s;        
        BIG order = new BIG(ROM.CURVE_Order);
        
        //testing new intersection function
        ArrayList<String>[] result = findSame(threshold, cred.get_A(), Aprime);
        BIG[] m;     //remains in A
        BIG[] w = new BIG[result[0].size()];    //intersected set
        BIG[] barw; //remains in A'
               
        
        //threshold must >0
        for(int i=0;i<w.length;i++){
            byte[] temp = H.digest(result[0].get(i).getBytes());
            byte[] hash = new byte[CONFIG_BIG.MODBYTES];
                for(int j=0;j<hash.length;j++){
                    if(j<temp.length)
                        hash[j]=temp[j];
                    else
                        hash[j]=0x00;
                }
            w[i] = BIG.fromBytes(hash);
            w[i].mod(order);
        }
        w = MPEncode(w,order);   
        
        if(threshold<cred.get_A().length){            
            m = syntheticDivision(cred.get_alphas(),w)[0];
        }
        else{
            m = new BIG[1];
            m[0] = new BIG();
            m[0].one();
        }             
        
        if(result[1].size()>0){
            barw = new BIG[result[1].size()];
            for(int i=0;i<barw.length;i++){
                byte[] temp = H.digest(result[1].get(i).getBytes());
                byte[] hash = new byte[CONFIG_BIG.MODBYTES];
                for(int j=0;j<hash.length;j++){
                    if(j<temp.length)
                        hash[j]=temp[j];
                    else
                        hash[j]=0x00;
                }
                barw[i] = BIG.fromBytes(hash);
                barw[i].mod(order);
            }
            
            barw = MPEncode(barw,order);        
        }
        else{
            barw = new BIG[1];
            barw[0] = new BIG();
            barw[0].one();
        }
                
        SecureRandom rand = new SecureRandom();
        RNG.clean();
	RNG.seed(100,rand.generateSeed(100));
        
        //prover sends commitment and witnesses        
        BIG[] _omega = new BIG[w.length];
        
        r = BIG.randomnum(order,RNG);
        y = BIG.randomnum(order,RNG);
        BIG yinv=new BIG(y);
        yinv.invmodp(order);
        _r = BIG.randomnum(order,RNG);
        _y = BIG.randomnum(order,RNG);
        _ty = BIG.randomnum(order,RNG);
        _s = BIG.randomnum(order,RNG);
        
        ECP V1 = PAIR256.G1mul(cred.get_v(), BIG.modmul(BIG.modmul(r, r, order), yinv, order));
        ECP V2 = PAIR256.G1mul(V1, _y);
        
        ECP M = PAIR256.G1mul(pk.get_a0(),m[0]);
        for(int i=1;i<m.length;i++){
            M.add(PAIR256.G1mul(pk.get_a()[i], m[i]));
        }
        M = PAIR256.G1mul(M, r);
        
        ECP Y1 = PAIR256.G1mul(V1, _ty);
        Y1.add(PAIR256.G1mul(pk.get_c(), _r));
        Y1.add(PAIR256.G1mul(pk.get_b(), _s));        
        
        ECP barW = PAIR256.G1mul(pk.get_a0(),barw[0]);
        for(int i=1;i<barw.length;i++){
            barW.add(PAIR256.G1mul(pk.get_a()[i], barw[i]));
        }
        BIG rinv = new BIG(r);
        rinv.invmodp(order);
        barW=PAIR256.G1mul(barW, rinv);
        
        _omega[0] = BIG.randomnum(order,RNG);
        ECP8 Y2 = PAIR256.G2mul(pk.get_g2(),_omega[0]);
        for(int i=1;i<_omega.length;i++){
            _omega[i] = BIG.randomnum(order,RNG);
            Y2.add(PAIR256.G2mul(pk.get_X()[i], _omega[i]));
        }                
        
        //verifier replies a challenge
        BIG e = BIG.randomnum(order,RNG);
        
      
        //prover sends response
        //\hat{r}=\tilde{r}+e^2r^2
        _r.add(BIG.modmul(e, BIG.modmul(r,r,order), order));    
        _r.mod(order);
        //\hat{y}=\tilde{y}+e^2y
        _y.add(BIG.modmul(e, y, order));        
        _y.mod(order);
        //\hat{t_y}=\tilde{t_y}-e^2ty
        _ty.sub(BIG.modmul(e, BIG.modmul(cred.get_t(), y, order), order));  
        _ty.mod(order);
        //\hat{s}=\tilde{s}+e^2sr^2
        _s.add(BIG.modmul(e, BIG.modmul(cred.get_s(),BIG.modmul(r,r,order),order), order));
        _s.mod(order);
        
        for(int i=0;i<_omega.length;i++){
            _omega[i].add(BIG.modmul(e, BIG.modmul(w[i],r,order), order));
            _omega[i].mod(order);
        }
        
        //verifier checks        
        //new checking, only 3 pairings
        FP48[] ll=PAIR256.initmp();	       
        
        ECP8 temp2 = PAIR256.G2mul(pk.get_g2(), _omega[0]);        
        for(int i=1;i<_omega.length;i++){
            temp2.add(PAIR256.G2mul(pk.get_X()[i], _omega[i]));            
        }
        temp2.sub(Y2);
        barW.add(M);
        PAIR256.another(ll,temp2, barW);
        
        BIG[] z = new BIG[Aprime.length];
        for(int i=0;i<Aprime.length;i++){
            byte[] temp = H.digest(Aprime[i].getBytes());
            byte[] hash = new byte[CONFIG_BIG.MODBYTES];
                for(int j=0;j<hash.length;j++){
                    if(j<temp.length)
                        hash[j]=temp[j];
                    else
                        hash[j]=0x00;
                }
            z[i] = BIG.fromBytes(hash);  
            z[i].mod(order);
        }
        z = MPEncode(z, order);
        ECP temp=PAIR256.G1mul(pk.get_a()[0], z[0]);
        for(int i=1;i<z.length;i++){
            temp.add(PAIR256.G1mul(pk.get_a()[i], z[i]));            
        }
        temp=PAIR256.G1mul(temp, e);
        temp.neg();
        temp.sub(Y1);
        temp.add(PAIR256.G1mul(pk.get_b(), _s));
        temp.add(PAIR256.G1mul(pk.get_c(), _r));
        temp.add(PAIR256.G1mul(V1, _ty));
        
	PAIR256.another(ll,pk.get_g2(), temp);
	FP48 left=PAIR256.fexp(PAIR256.miller(ll));
                       
        
        temp = PAIR256.G1mul(V1, _y);
        temp.sub(V2);
       
        
	FP48 right=PAIR256.fexp(PAIR256.ate(pk.get_g2x(), temp));
        
                
        if(left.equals(right))
            return true;
        else{
            return false;
        }
        }
        catch(NoSuchAlgorithmException e){
            Logger.getLogger(SDHABC.class.getName()).log(Level.SEVERE, null, e);
        } catch (Exception ex) {
            Logger.getLogger(SDHABC.class.getName()).log(Level.SEVERE, null, ex);
            throw new Exception("ANY proof: "+ex.getMessage());            
        }
        
        return false;
    }
    
    /**
     * ABC NAND Proof protocol.
     * 
     * @param pk ABC public key.
     * @param cred ABC credential.
     * @param Aprime query attribute set.
     * 
     * @throws Exception if the searching for differing attributes fails or the protocol fails.
     * 
     * @return true if A' is disjoint to A, false otherwise.
     */
    public boolean proofOfNAND(ABCpk pk, ABCcred cred, String[] Aprime) throws Exception{
        try{
        MessageDigest H = MessageDigest.getInstance("SHA-512");
        RAND RNG = new RAND();
        BIG r,y,_r,_y,_ty,_s;        
        BIG order = new BIG(ROM.CURVE_Order);
        BIG[] w, d, barr;
        BIG[][] barw;
        
        //if threshold doesn't met, exception thrown
        //so, we don't need to perform a check anymore
        ArrayList<String>[] result = findNotSame(Aprime.length,cred.get_A(),Aprime);                
                
        //those not-same attributes        
        BIG[] m = new BIG[result[0].size()];
        for(int i=0;i<m.length;i++){            
            byte[] temp = H.digest(result[0].get(i).getBytes());
                byte[] hash = new byte[CONFIG_BIG.MODBYTES];
                for(int j=0;j<hash.length;j++){
                    if(j<temp.length)
                        hash[j]=temp[j];
                    else
                        hash[j]=0x00;
                }
            m[i] = BIG.fromBytes(hash);
            m[i].mod(order);
        }
                
        BIG[][] division = syntheticDivision(cred.get_alphas(),
                                             MPEncode(m, order));
        w = division[0]; //quotient
        d = division[1]; //remainder
        
        barw = new BIG[m.length][division[1].length-1]; 
        barr = new BIG[m.length]; 
        for(int i=0;i<m.length;i++){
            BIG[] m_i = new BIG[1];
            m_i[0] = new BIG(m[i]);
            division = syntheticDivision(d, MPEncode(m_i, order));
            
            for(int j=0;j<division[0].length;j++){
                barw[i][j] = division[0][j];
            }
             
            barr[i] = division[1][0];            
        }
        
        SecureRandom rand = new SecureRandom();
        RNG.clean();
	RNG.seed(100,rand.generateSeed(100));
        
        
        r = BIG.randomnum(order,RNG);
        y = BIG.randomnum(order,RNG);
        BIG yinv=new BIG(y);
        yinv.invmodp(order);
        _r = BIG.randomnum(order,RNG);
        _y = BIG.randomnum(order,RNG);
        _ty = BIG.randomnum(order,RNG);
        _s = BIG.randomnum(order,RNG);
        
        ECP vprime = PAIR256.G1mul(cred.get_v(), BIG.modmul(r, yinv, order));
        ECP V = PAIR256.G1mul(vprime, _y);
                
        ECP W = PAIR256.G1mul(pk.get_a0(),w[0]);
        for(int i=1;i<w.length;i++){
            W.add(PAIR256.G1mul(pk.get_a()[i], w[i]));
        }
        W = PAIR256.G1mul(W, r);
        
        ECP R = PAIR256.G1mul(pk.get_a0(),d[0]);
        for(int i=1;i<d.length;i++){
            R.add(PAIR256.G1mul(pk.get_a()[i], d[i]));
        }
        R = PAIR256.G1mul(R, r);
        
        ECP[] barWi = new ECP[barw.length];
        
        for(int i=0;i<barw.length;i++){
            barWi[i] = PAIR256.G1mul(pk.get_a0(),barw[i][0]);
            for(int j=1;j<barw[i].length;j++){
                barWi[i].add(PAIR256.G1mul(pk.get_a()[j], barw[i][j]));
            }
            barWi[i] = PAIR256.G1mul(barWi[i], r);
        }
        
        
        ECP[] Ri = new ECP[barr.length];
        for(int i=0;i<barr.length;i++){
            Ri[i] = PAIR256.G1mul(pk.get_a0(),barr[i]);
            Ri[i] = PAIR256.G1mul(Ri[i], r);
        }
                    
        
        ECP Y = PAIR256.G1mul(vprime, _ty);
        Y.add(PAIR256.G1mul(pk.get_c(), _r));
        Y.add(PAIR256.G1mul(pk.get_b(), _s));        
        
        //verifier replies a challenge
        BIG e = BIG.randomnum(order,RNG);        
      
        //prover sends response
        //\hat{r}=\tilde{r}+er
        _r.add(BIG.modmul(e, r, order));
        _r.mod(order);        
        //\hat{y}=\tilde{y}+ey
        _y.add(BIG.modmul(e, y, order));        
        _y.mod(order);
        //\hat{t_y}=\tilde{t_y}-ety
        _ty.sub(BIG.modmul(e, BIG.modmul(cred.get_t(), y, order), order));  
        _ty.mod(order);
        //\hat{s}=\tilde{s}+esr
        _s.add(BIG.modmul(e, BIG.modmul(cred.get_s(),r,order), order));
        _s.mod(order);
        
        
        //verifier checks        
        //new checking, only 3 pairings 
        FP48[] ll=PAIR256.initmp();       
        if(R.is_infinity() || W.is_infinity()){
            return false;
        }
        for(int i=0;i<barWi.length;i++){
            if(Ri[i].is_infinity() || barWi[i].is_infinity()){
                return false;
            }
        }
        
        BIG exp = new BIG();
        exp.one();
        for(int i=0;i<Aprime.length;i++){
            exp.add(new BIG(i+1));
        }
        
        ECP temp = PAIR256.G1mul(R, BIG.modmul(e, exp, order));
           
        for(int i=0;i<barWi.length;i++){
            temp.sub(PAIR256.G1mul(barWi[i], BIG.modmul(e, BIG.modmul(m[i], new BIG(i+1), order), order)));
            temp.sub(PAIR256.G1mul(Ri[i], BIG.modmul(e, new BIG(i+1), order)));
        }
        
        temp.add(PAIR256.G1mul(pk.get_b(), _s));
        temp.add(PAIR256.G1mul(pk.get_c(), _r));
        temp.add(PAIR256.G1mul(vprime, _ty));        
        temp.sub(Y);
	PAIR256.another(ll,pk.get_g2(), temp);
	
        ECP temp1 = PAIR256.G1mul(W, e);        
        
        m = new BIG[Aprime.length];
        for(int i=0;i<Aprime.length;i++){
           byte[] temph = H.digest(Aprime[i].getBytes());
                byte[] hash = new byte[CONFIG_BIG.MODBYTES];
                for(int j=0;j<hash.length;j++){
                    if(j<temph.length)
                        hash[j]=temph[j];
                    else
                        hash[j]=0x00;
                }
            m[i] = BIG.fromBytes(hash);
            m[i].mod(order);
        }
        m = MPEncode(m, order);
        
        ECP8 temp2 = PAIR256.G2mul(pk.get_g2(), m[0]);
        for(int i=1;i<m.length;i++){
            temp2.add(PAIR256.G2mul(pk.get_X()[i], m[i]));            
        }
        
        PAIR256.another(ll,temp2, temp1);                        
	FP48 left=PAIR256.fexp(PAIR256.miller(ll));
                       
        
        temp = PAIR256.G1mul(vprime, _y);
        temp.sub(V);
       
        
	FP48 right=PAIR256.ate(pk.get_g2x(), temp);
        
        temp = new ECP();
        temp.inf();
        for(int i=0;i<barWi.length;i++){
            temp.add(barWi[i]);
        }
        temp = PAIR256.G1mul(temp, e);
        
        right.mul(PAIR256.ate(pk.get_X()[2], temp));
        
        temp = new ECP();
        temp.inf();
        m = new BIG[Aprime.length];
        for(int i=0;i<Aprime.length;i++){
            byte[] temph = H.digest(Aprime[i].getBytes());
                byte[] hash = new byte[CONFIG_BIG.MODBYTES];
                for(int j=0;j<hash.length;j++){
                    if(j<temph.length)
                        hash[j]=temph[j];
                    else
                        hash[j]=0x00;
                }
            m[i] = BIG.fromBytes(hash);
            m[i].mod(order);
        }
        for(int i=0;i<barWi.length;i++){
            exp = new BIG(m[i]);
            exp.add(new BIG(i+1));
            
            temp.add(PAIR256.G1mul(barWi[i], BIG.modmul(e, exp, order)));
            temp.add(PAIR256.G1mul(Ri[i], e));
        } 
        temp.sub(PAIR256.G1mul(R, BIG.modmul(e, new BIG(Aprime.length), order)));
        
        right.mul(PAIR256.ate(pk.get_X()[1],temp));
                
        if(left.equals(PAIR256.fexp(right))){
            return true;
        }
        else{
            return false;
        }
        }
        catch(NoSuchAlgorithmException e){
            Logger.getLogger(SDHABC.class.getName()).log(Level.SEVERE, null, e);
        } catch (Exception ex) {
            Logger.getLogger(SDHABC.class.getName()).log(Level.SEVERE, null, ex);
            throw new Exception("NAND proof: "+ex.getMessage());            
        }
        
        return false;
    }
    
    /**
     * ABC NANY Proof protocol.
     * 
     * @param pk ABC public key.
     * @param cred ABC credential.
     * @param threshold the threshold \bar{\ell} is at most |A'| and at most |A|.
     * @param Aprime query attribute set.
     * 
     * @throws Exception if the searching for differing attributes fails or the protocol fails.
     * 
     * @return true if |A' - A| graeter than or equals to threshold, false otherwise.
     */
    public boolean proofOfNANY(ABCpk pk, ABCcred cred, int threshold, String[] Aprime) throws Exception{
        try{
        MessageDigest H = MessageDigest.getInstance("SHA-512");
        RAND RNG = new RAND();
        BIG r,y,_r,_y,_ty,_s,mu1,mu0,invmu0,invmu1,_mu1,_mu0;
        BIG[] _di0,_di1;        
        BIG order = new BIG(ROM.CURVE_Order);
        BIG[] w, mathsf_r;
        
        //if threshold doesn't met, exception thrown
        //so, we don't need to perform a check anymore
        ArrayList<String>[] result = findNotSame(threshold,cred.get_A(),Aprime);                
                
        //those not-same attributes D       
        BIG[] d = new BIG[result[0].size()];
        for(int i=0;i<d.length;i++){            
            byte[] temp = H.digest(result[0].get(i).getBytes());
                byte[] hash = new byte[CONFIG_BIG.MODBYTES];
                for(int j=0;j<hash.length;j++){
                    if(j<temp.length)
                        hash[j]=temp[j];
                    else
                        hash[j]=0x00;
                }
            d[i] = BIG.fromBytes(hash);
            d[i].mod(order);
        }
        d = MPEncode(d, order);
        
        //compute witness D_\bar{l} for the divisor D
        ECP8 D_bar_l = new ECP8();
        for(int i=0;i<d.length;i++){
            D_bar_l.add(PAIR256.G2mul(pk.get_X()[i], d[i]));
        }
        
        //those remaining attributes in A', i.e., A'-D, can be mixture of same and not same
        BIG[] m2 = new BIG[result[1].size()];
        for(int i=0;i<m2.length;i++){            
            byte[] temp = H.digest(result[1].get(i).getBytes());
                byte[] hash = new byte[CONFIG_BIG.MODBYTES];
                for(int j=0;j<hash.length;j++){
                    if(j<temp.length)
                        hash[j]=temp[j];
                    else
                        hash[j]=0x00;
                }
            m2[i] = BIG.fromBytes(hash);
            m2[i].mod(order);
        }
        m2 = MPEncode(m2, order);
        
        //compute witness W' for A'-D
        ECP Wprime = PAIR256.G1mul(pk.get_a0(),m2[0]);
        for(int i=1;i<m2.length;i++){
            Wprime.add(PAIR256.G1mul(pk.get_a()[i], m2[i]));
        }
        
        BIG[][] division = syntheticDivision(cred.get_alphas(),d);
        w = division[0]; //quotient
        mathsf_r = division[1]; //remainder
                     
        //compute witness W for quotient
        ECP W = new ECP();
        for(int i=0;i<w.length;i++){
            W.add(PAIR256.G1mul(pk.get_a()[i], w[i]));
        }
        
        //compute witness R for remainder
        ECP R = new ECP();
        for(int i=0;i<mathsf_r.length;i++){
            R.add(PAIR256.G1mul(pk.get_a()[i], mathsf_r[i]));            
        }
        
        SecureRandom rand = new SecureRandom();
        RNG.clean();
	RNG.seed(100,rand.generateSeed(100));
        
        r = BIG.randomnum(order,RNG);
        y = BIG.randomnum(order,RNG);
        BIG yinv=new BIG(y);
        yinv.invmodp(order);
        _r = BIG.randomnum(order,RNG);
        _y = BIG.randomnum(order,RNG);
        _ty = BIG.randomnum(order,RNG);
        _s = BIG.randomnum(order,RNG);
        mu1 = BIG.randomnum(order,RNG);
        invmu1 = new BIG(mu1);
        invmu1.invmodp(order);
        mu0 = BIG.randomnum(order,RNG);
        invmu0 = new BIG(mu0);
        invmu0.invmodp(order);
        _mu1 = BIG.randomnum(order,RNG);
        _mu0 = BIG.randomnum(order,RNG);
        
        _di0 = new BIG[threshold];
        _di1 = new BIG[threshold];
        for(int i=0;i<threshold;i++){
            _di0[i] = BIG.randomnum(order,RNG);
            _di1[i] = BIG.randomnum(order,RNG);
        }
        
        ECP vprime = PAIR256.G1mul(cred.get_v(), BIG.modmul(r.powmod(new BIG(threshold+1), order), yinv, order));
        ECP V = PAIR256.G1mul(vprime, _y);
        
        //randomize the witnesses
        W = PAIR256.G1mul(W, r);
        R = PAIR256.G1mul(R, r.powmod(new BIG(threshold+1), order));
        
        BIG rinv = r.powmod(new BIG(threshold), order);
        rinv.invmodp(order);
        Wprime = PAIR256.G1mul(Wprime, rinv);
                
        D_bar_l = PAIR256.G2mul(D_bar_l, r.powmod(new BIG(threshold), order));
        
        
        //compute witnesses D_i and its bar{W}_i, R_i for R=bar{W}_i^{x'+d_j}R_i       
        d = new BIG[result[0].size()];//result[0].size() equals to threshold
        ECP[] Di = new ECP[d.length-1];
        ECP[] barWi = new ECP[d.length];
        ECP[] barWiprime = new ECP[d.length];
        ECP[] Ri = new ECP[d.length];
        for(int i=0;i<d.length;i++){            
            byte[] temp = H.digest(result[0].get(i).getBytes());
                byte[] hash = new byte[CONFIG_BIG.MODBYTES];
                for(int j=0;j<hash.length;j++){
                    if(j<temp.length)
                        hash[j]=temp[j];
                    else
                        hash[j]=0x00;
                }
            d[i] = BIG.fromBytes(hash);
            d[i].mod(order);
            
            BIG[] tmp = new BIG[i+1];
            for(int j=0;j<tmp.length;j++){
                tmp[j] = new BIG(d[j]);
            }
            tmp = MPEncode(tmp, order);
            
            if(i<Di.length){
                Di[i] = new ECP();
                for(int j=0;j<tmp.length;j++){
                    Di[i].add(PAIR256.G1mul(pk.get_a()[j], tmp[j]));
                }
                Di[i] = PAIR256.G1mul(Di[i], r.powmod(new BIG(i+1), order));
            }
            tmp = new BIG[1];
            tmp[0] = new BIG(d[i]);            
            BIG[][] div = syntheticDivision(mathsf_r,MPEncode(tmp,order));
            BIG[] barw = div[0]; //quotient
            BIG barmathsf_r = div[1][0]; //remainder
            
            barWi[i] = new ECP();
            barWiprime[i] = new ECP();
            for(int j=0;j<barw.length;j++){
                barWi[i].add(PAIR256.G1mul(pk.get_a()[j], barw[j]));
                barWiprime[i].add(PAIR256.G1mul(pk.get_a()[j+1], barw[j]));
            }
            barWi[i] = PAIR256.G1mul(barWi[i], r.powmod(new BIG(threshold), order));
            barWiprime[i] = PAIR256.G1mul(barWiprime[i], r.powmod(new BIG(threshold), order));
            
            Ri[i] = PAIR256.G1mul(pk.get_a0(), BIG.modmul(barmathsf_r,r.powmod(new BIG(threshold+1), order), order));       
            
            /*
            //check      
            System.out.println("R="+R);
            System.out.println("d["+i+"]="+result[0].get(i));
            System.out.println("barWi["+i+"]="+barWi[i]);
            System.out.println("Ri["+i+"]="+Ri[i]);
            FP12 lhs = PAIR.ate(pk.get_g2(), R);
            FP12 rhs = PAIR.ate(PAIR.G2mul(pk.get_g2(), BIG.modmul(d[i], r, order)), barWi[i]);
            rhs.mul(PAIR.ate(PAIR.G2mul(pk.get_X()[1], r), barWi[i]));
            rhs.mul(PAIR.ate(pk.get_g2(), Ri[i]));
            System.out.println(i+", LHS:"+PAIR.fexp(lhs));
            System.out.println(i+", RHS:"+PAIR.fexp(rhs));
            //check done
            */
        }
        
        /*
        //check Di
        ECP tempDi = new ECP();
        for(int i=0;i<Di.length;i++){
            tempDi.add(Di[i]);
        }
        FP12 lhs = PAIR.ate(pk.get_g2(), tempDi);
        lhs.mul(PAIR.ate(D_bar_l, pk.get_a0()));
        
        tempDi = new ECP();
        for(int i=0;i<d.length;i++){
            if(i==0){
                tempDi.add(PAIR.G1mul(pk.get_a0(), r));
            }
            else{
                tempDi.add(PAIR.G1mul(Di[i-1], r));
            }
        }
        FP12 rhs = PAIR.ate(pk.get_X()[1], tempDi);
        
        tempDi = new ECP();
        for(int i=0;i<d.length;i++){
            if(i==0){
                tempDi.add(PAIR.G1mul(pk.get_a0(), BIG.modmul(r, d[i], order)));
            }
            else{
                tempDi.add(PAIR.G1mul(Di[i-1], BIG.modmul(r, d[i], order)));
            }
        }
        rhs.mul(PAIR.ate(pk.get_X()[0], tempDi));
        System.out.println(PAIR.fexp(lhs));
        System.out.println(PAIR.fexp(rhs));
        //done check
        */
        
        ECP Y1 = PAIR256.G1mul(vprime, _ty);
        Y1.add(PAIR256.G1mul(pk.get_c(), _r));
        Y1.add(PAIR256.G1mul(pk.get_b(), _s));
                
        ECP Y2 = new ECP();
        ECP Y3 = new ECP();
        for(int i=0;i<threshold;i++){
            ECP temp = new ECP();
            if(i==0){
                temp.add(pk.get_a0());
            }
            else{
                temp.add(Di[i-1]);
            }
            temp.add(barWiprime[i]);
            temp.add(PAIR256.G1mul(barWi[i], new BIG(i+1)));
            Y2.add(PAIR256.G1mul(temp, _di1[i]));
            Y3.add(PAIR256.G1mul(temp, _di0[i]));
        }
                                
        ECP8 Y4 = PAIR256.G2mul(pk.get_X()[1], _mu1);
        ECP8 Y5 = PAIR256.G2mul(pk.get_X()[0], _mu0);
        
        //verifier replies a challenge
        BIG e = BIG.randomnum(order,RNG);        
      
        //prover sends response
        //\hat{r}=\tilde{r}+er^{bar{l}+1}
        _r.add(BIG.modmul(e, r.powmod(new BIG(threshold+1), order), order));
        _r.mod(order);        
        //\hat{y}=\tilde{y}+ey
        _y.add(BIG.modmul(e, y, order));        
        _y.mod(order);
        //\hat{t_y}=\tilde{t_y}-ety
        _ty.sub(BIG.modmul(e, BIG.modmul(cred.get_t(), y, order), order));  
        _ty.mod(order);
        //\hat{s}=\tilde{s}+esr^{bar{l}+1}
        _s.add(BIG.modmul(e, BIG.modmul(cred.get_s(),r.powmod(new BIG(threshold+1), order),order), order));
        _s.mod(order);
        _mu1.add(BIG.modmul(e, mu1, order));
        _mu1.mod(order);
        _mu0.add(BIG.modmul(e, mu0, order));
        _mu0.mod(order);    
        
        for(int i=0;i<threshold;i++){
            _di1[i].add(BIG.modmul(e, BIG.modmul(r, invmu1, order), order));
            _di1[i].mod(order);
            _di0[i].add(BIG.modmul(e, BIG.modmul(BIG.modmul(r, invmu0, order),d[i],order), order));
            _di0[i].mod(order);
        }
        
        //verifier checks        
        if(W.is_infinity() || R.is_infinity()){
            return false;
        }
        for(int i=0;i<threshold;i++){
            if(threshold>1)
            if(barWi[i].is_infinity() || Ri[i].is_infinity()){
                return false;
            }
        }
        
        
        //first pairing at lhs
        ECP temp = new ECP(Wprime);
        temp.add(W);
        temp.add(pk.get_a0());
        //FP12 lhs = PAIR.ate(D_bar_l, PAIR.G1mul(temp, e));
        FP48[] ll=PAIR256.initmp();
        PAIR256.another(ll, D_bar_l, PAIR256.G1mul(temp, e));
            
        //second pairing at lhs
        temp = PAIR256.G1mul(R, new BIG(threshold));
        for(int i=0;i<threshold;i++){
            temp.add(barWi[i]);
            temp.sub(Ri[i]);
        }
        //lhs.mul(PAIR.ate(pk.get_X()[1], PAIR.G1mul(temp, e)));
        PAIR256.another(ll,pk.get_X()[1], PAIR256.G1mul(temp, e));
        
        //third pairing at lhs
        temp = new ECP();
        //temp.add(PAIR.G1mul(R, e));
        int num = 1;
        temp = new ECP();
        for(int i=0;i<threshold;i++){
            num += i+1;
        }
        temp.add(PAIR256.G1mul(R, new BIG(num)));
        
        for(int i=0;i<threshold;i++){
            temp.sub(barWiprime[i]);
            temp.sub(PAIR256.G1mul(Ri[i], new BIG(i+1)));
        }
        temp = PAIR256.G1mul(temp, e);
        
        temp.add(PAIR256.G1mul(pk.get_b(), _s));
        temp.add(PAIR256.G1mul(pk.get_c(), _r));
        temp.add(PAIR256.G1mul(vprime, _ty));        
        temp.sub(Y1);
        
        BIG[] m1 = new BIG[Aprime.length];
        for(int i=0;i<Aprime.length;i++){
            byte[] temph = H.digest(Aprime[i].getBytes());
                byte[] hash = new byte[CONFIG_BIG.MODBYTES];
                for(int j=0;j<hash.length;j++){
                    if(j<temph.length)
                        hash[j]=temph[j];
                    else
                        hash[j]=0x00;
                }
            m1[i] = BIG.fromBytes(hash);
            m1[i].mod(order);
        }
        m1 = MPEncode(m1, order);
        
        ECP tempp = new ECP();
        for(int i=0;i<m1.length;i++){
            tempp.add(PAIR256.G1mul(pk.get_a()[i], m1[i]));            
        }
        temp.sub(PAIR256.G1mul(tempp, e));
                
        tempp = new ECP();
        for(int i=0;i<Di.length;i++){
            tempp.add(Di[i]);
        }
        temp.add(PAIR256.G1mul(tempp, e));
        //lhs.mul(PAIR.ate(pk.get_g2(), temp));
        PAIR256.another(ll, pk.get_g2(), temp);
        
        //3rd pairing at rhs
        temp = PAIR256.G1mul(vprime, _y);
        temp.sub(V);
        //FP12 rhs = PAIR.ate(pk.get_g2x(), temp);
        FP48[] rr=PAIR256.initmp();
        PAIR256.another(rr, pk.get_g2x(), temp);
                
        
        //2nd pairing at rhs
        temp = new ECP();
        
        for(int i=0;i<threshold;i++){
            tempp = new ECP();
            if(i==0){
                tempp.add(pk.get_a0());
            }
            else{
                tempp.add(Di[i-1]);
            }
            tempp.add(barWiprime[i]);
            tempp.add(PAIR256.G1mul(barWi[i], new BIG(i+1)));            
            temp.add(PAIR256.G1mul(tempp, _di0[i]));
        }        
        temp.sub(Y3);
        ECP8 X0mu0 = PAIR256.G2mul(pk.get_g2(), _mu0);
        X0mu0.sub(Y5);
        BIG invee = new BIG(e);
        invee.invmodp(order);
        //rhs.mul(PAIR.ate(X0mu0, PAIR.G1mul(temp, invee)));
        PAIR256.another(rr, X0mu0, PAIR256.G1mul(temp, invee));
        
        temp = new ECP();
        
        for(int i=0;i<threshold;i++){
            tempp = new ECP();
            if(i==0){
                tempp.add(pk.get_a0());
            }
            else{
                tempp.add(Di[i-1]);
            }
            tempp.add(barWiprime[i]);
            tempp.add(PAIR256.G1mul(barWi[i], new BIG(i+1)));            
            temp.add(PAIR256.G1mul(tempp, _di1[i]));
        }        
        temp.sub(Y2);
        ECP8 X1mu1 = PAIR256.G2mul(pk.get_X()[1], _mu1);
        X1mu1.sub(Y4);
        //rhs.mul(PAIR.ate(X1mu1, PAIR.G1mul(temp, invee)));
        PAIR256.another(rr,X1mu1, PAIR256.G1mul(temp, invee));
                
        FP48 left=PAIR256.fexp(PAIR256.miller(ll));
        FP48 right=PAIR256.fexp(PAIR256.miller(rr));
                        
        if(left.equals(right)){
            return true;
        }
        else{
            return false;
        }
        }
        catch(NoSuchAlgorithmException e){
            Logger.getLogger(SDHABC.class.getName()).log(Level.SEVERE, null, e);
        } catch (Exception ex) {
            Logger.getLogger(SDHABC.class.getName()).log(Level.SEVERE, null, ex);
            throw new Exception("NANY proof: "+ex.getMessage());            
        }
        
        return false;
    }
    
    //Flawed, leak info for compressed, kept for reference
    public boolean flawedproofOfNANY(ABCpk pk, ABCcred cred, int threshold, String[] Aprime) throws Exception{
        try{
        MessageDigest H = MessageDigest.getInstance("SHA-512");
        RAND RNG = new RAND();
        BIG r,y,_r,_y,_ty,_s;
        BIG[] _di0,_di1;        
        BIG order = new BIG(ROM.CURVE_Order);
        BIG[] w, mathsf_r;
        
        //if threshold doesn't met, exception thrown
        //so, we don't need to perform a check anymore
        ArrayList<String>[] result = findNotSame(threshold,cred.get_A(),Aprime);                
                
        //those not-same attributes D       
        BIG[] d = new BIG[result[0].size()];
        for(int i=0;i<d.length;i++){            
            byte[] temp = H.digest(result[0].get(i).getBytes());
                byte[] hash = new byte[CONFIG_BIG.MODBYTES];
                for(int j=0;j<hash.length;j++){
                    if(j<temp.length)
                        hash[j]=temp[j];
                    else
                        hash[j]=0x00;
                }
            d[i] = BIG.fromBytes(hash);
            d[i].mod(order);
        }
        d = MPEncode(d, order);
        
        //compute witness D_\bar{l} for the divisor D
        ECP8 D_bar_l = new ECP8();
        for(int i=0;i<d.length;i++){
            D_bar_l.add(PAIR256.G2mul(pk.get_X()[i], d[i]));
        }
        
        //those remaining attributes in A', i.e., A'-D, can be mixture of same and not same
        BIG[] m2 = new BIG[result[1].size()];
        for(int i=0;i<m2.length;i++){            
            byte[] temp = H.digest(result[1].get(i).getBytes());
                byte[] hash = new byte[CONFIG_BIG.MODBYTES];
                for(int j=0;j<hash.length;j++){
                    if(j<temp.length)
                        hash[j]=temp[j];
                    else
                        hash[j]=0x00;
                }
            m2[i] = BIG.fromBytes(hash);
            m2[i].mod(order);
        }
        m2 = MPEncode(m2, order);
        
        //compute witness W' for A'-D
        ECP Wprime = PAIR256.G1mul(pk.get_a0(),m2[0]);
        for(int i=1;i<m2.length;i++){
            Wprime.add(PAIR256.G1mul(pk.get_a()[i], m2[i]));
        }
        
        BIG[][] division = syntheticDivision(cred.get_alphas(),d);
        w = division[0]; //quotient
        mathsf_r = division[1]; //remainder
                     
        //compute witness W for quotient
        ECP W = new ECP();
        for(int i=0;i<w.length;i++){
            W.add(PAIR256.G1mul(pk.get_a()[i], w[i]));
        }
        
        //compute witness R for remainder
        ECP R = new ECP();
        for(int i=0;i<mathsf_r.length;i++){
            R.add(PAIR256.G1mul(pk.get_a()[i], mathsf_r[i]));            
        }
        
        SecureRandom rand = new SecureRandom();
        RNG.clean();
	RNG.seed(100,rand.generateSeed(100));
        
        r = BIG.randomnum(order,RNG);
        y = BIG.randomnum(order,RNG);
        BIG yinv=new BIG(y);
        yinv.invmodp(order);
        _r = BIG.randomnum(order,RNG);
        _y = BIG.randomnum(order,RNG);
        _ty = BIG.randomnum(order,RNG);
        _s = BIG.randomnum(order,RNG);
        
        _di0 = new BIG[threshold];
        _di1 = new BIG[threshold];
        for(int i=0;i<threshold;i++){
            _di0[i] = BIG.randomnum(order,RNG);
            _di1[i] = BIG.randomnum(order,RNG);
        }
        
        ECP vprime = PAIR256.G1mul(cred.get_v(), BIG.modmul(r.powmod(new BIG(threshold+1), order), yinv, order));
        ECP V = PAIR256.G1mul(vprime, _y);
        
        //randomize the witnesses
        W = PAIR256.G1mul(W, r);
        R = PAIR256.G1mul(R, r.powmod(new BIG(threshold+1), order));
        
        BIG rinv = r.powmod(new BIG(threshold), order);
        rinv.invmodp(order);
        Wprime = PAIR256.G1mul(Wprime, rinv);
                
        D_bar_l = PAIR256.G2mul(D_bar_l, r.powmod(new BIG(threshold), order));
        
        
        //compute witnesses D_i and its bar{W}_i, R_i for R=bar{W}_i^{x'+d_j}R_i       
        d = new BIG[result[0].size()];//result[0].size() equals to threshold
        ECP[] Di = new ECP[d.length-1];
        ECP[] barWi = new ECP[d.length];
        ECP[] Ri = new ECP[d.length];
        for(int i=0;i<d.length;i++){            
            byte[] temp = H.digest(result[0].get(i).getBytes());
                byte[] hash = new byte[CONFIG_BIG.MODBYTES];
                for(int j=0;j<hash.length;j++){
                    if(j<temp.length)
                        hash[j]=temp[j];
                    else
                        hash[j]=0x00;
                }
            d[i] = BIG.fromBytes(hash);
            d[i].mod(order);
            
            BIG[] tmp = new BIG[i+1];
            for(int j=0;j<i+1;j++){
                tmp[j] = new BIG(d[j]);
            }
            tmp = MPEncode(tmp, order);
            
            if(i<Di.length){
                Di[i] = new ECP();
                for(int j=0;j<tmp.length;j++){
                    Di[i].add(PAIR256.G1mul(pk.get_a()[j], tmp[j]));
                }
                Di[i] = PAIR256.G1mul(Di[i], r.powmod(new BIG(i+1), order));
            }
            tmp = new BIG[1];
            tmp[0] = new BIG(d[i]);            
            BIG[][] div = syntheticDivision(mathsf_r,MPEncode(tmp,order));
            BIG[] barw = div[0]; //quotient
            BIG[] barmathsf_r = div[1]; //remainder
            
            barWi[i] = new ECP();
            for(int j=0;j<barw.length;j++){
                barWi[i].add(PAIR256.G1mul(pk.get_a()[j], barw[j]));
            }
            barWi[i] = PAIR256.G1mul(barWi[i], r.powmod(new BIG(threshold), order));
            
            Ri[i] = PAIR256.G1mul(pk.get_a0(), BIG.modmul(barmathsf_r[0],r.powmod(new BIG(threshold+1), order), order));            
        }
                        
        ECP Y1 = PAIR256.G1mul(vprime, _ty);
        Y1.add(PAIR256.G1mul(pk.get_c(), _r));
        Y1.add(PAIR256.G1mul(pk.get_b(), _s));
                
        ECP Y2 = new ECP();
        for(int i=0;i<threshold;i++){
            ECP temp = new ECP();
            if(i==0){
                temp.add(pk.get_a0());
            }
            else{
                temp.add(Di[i-1]);
            }
            temp.add(PAIR256.G1mul(barWi[i], new BIG(i+1)));
            temp.neg();
            temp = PAIR256.G1mul(temp, _di0[i]);
            Y2.add(temp);
        }
        
        ECP Y3 = new ECP();
        for(int i=0;i<threshold;i++){
            Y3.add(PAIR256.G1mul(barWi[i], _di1[i]));
        }
        
        ECP Y4 = new ECP();
        for(int i=0;i<threshold;i++){
            ECP temp = new ECP();
            if(i==0){
                temp.add(pk.get_a0());
            }
            else{
                temp.add(Di[i-1]);
            }
            temp.add(PAIR256.G1mul(barWi[i], new BIG(i+1)));
            temp = PAIR256.G1mul(temp, _di1[i]);
            temp.add(PAIR256.G1mul(barWi[i], _di0[i]));
            Y4.add(temp);
        }
                
        
        //verifier replies a challenge
        BIG e = BIG.randomnum(order,RNG);        
      
        //prover sends response
        //\hat{r}=\tilde{r}+er^{bar{l}+1}
        _r.add(BIG.modmul(e, r.powmod(new BIG(threshold+1), order), order));
        _r.mod(order);        
        //\hat{y}=\tilde{y}+ey
        _y.add(BIG.modmul(e, y, order));        
        _y.mod(order);
        //\hat{t_y}=\tilde{t_y}-ety
        _ty.sub(BIG.modmul(e, BIG.modmul(cred.get_t(), y, order), order));  
        _ty.mod(order);
        //\hat{s}=\tilde{s}+esr^{bar{l}+1}
        _s.add(BIG.modmul(e, BIG.modmul(cred.get_s(),r.powmod(new BIG(threshold+1), order),order), order));
        _s.mod(order);
            
        
        for(int i=0;i<threshold;i++){
            _di1[i].add(BIG.modmul(e, r, order));
            _di1[i].mod(order);
            _di0[i].add(BIG.modmul(e, BIG.modmul(r,d[i],order), order));
            _di0[i].mod(order);
        }
        
        //verifier checks        
        if(W.is_infinity() || R.is_infinity()){
            for(int i=0;i<threshold;i++){
                if(barWi[i].is_infinity() || Ri[i].is_infinity()){
                    return false;
                }
            }
        }
        
        //2nd pairings at left hand side
        FP48[] ll=PAIR256.initmp();
        ECP temp = new ECP();
        
        //compute R^{e(1+sum_i=1^\bar{l} i)}
        int num = 1;
        for(int i=0;i<threshold;i++){
            num += i+1;
        }
        temp.add(PAIR256.G1mul(R, BIG.modmul(e, new BIG(num), order)));
        
        temp.add(PAIR256.G1mul(pk.get_b(), _s));
        temp.add(PAIR256.G1mul(pk.get_c(), _r));
        temp.add(PAIR256.G1mul(vprime, _ty));        
        temp.sub(Y1);
        
        BIG[] m1 = new BIG[Aprime.length];
        for(int i=0;i<Aprime.length;i++){
            byte[] temph = H.digest(Aprime[i].getBytes());
                byte[] hash = new byte[CONFIG_BIG.MODBYTES];
                for(int j=0;j<hash.length;j++){
                    if(j<temph.length)
                        hash[j]=temph[j];
                    else
                        hash[j]=0x00;
                }
            m1[i] = BIG.fromBytes(hash);
            m1[i].mod(order);
        }
        m1 = MPEncode(m1, order);
        
        ECP tempp = new ECP();
        for(int i=0;i<m1.length;i++){
            tempp.add(PAIR256.G1mul(pk.get_a()[i], m1[i]));            
        }
        temp.sub(PAIR256.G1mul(tempp, e));
        
        tempp = new ECP();
        for(int i=0;i<Di.length;i++){
            tempp.add(Di[i]);
        }
        temp.add(PAIR256.G1mul(tempp, e));
        
        for(int i=0;i<threshold;i++){
            tempp = new ECP();
            if(i==0){
                tempp.add(pk.get_a0());
            }
            else{
                tempp.add(Di[i-1]);
            }
            tempp.add(PAIR256.G1mul(barWi[i], new BIG(i+1)));
            tempp.neg();
            tempp = PAIR256.G1mul(tempp, _di0[i]);
            temp.add(tempp);
        }        
        temp.sub(Y2);
        
        
        tempp = new ECP();
        for(int i=0;i<threshold;i++){
            tempp.add(PAIR256.G1mul(Ri[i], new BIG(i+1)));
        }
        temp.sub(PAIR256.G1mul(tempp, e));
                
	PAIR256.another(ll,pk.get_g2(), temp);
	
        
        //1st pairing at left hand side
        Wprime.add(W);  
        Wprime.add(pk.get_a0());
        PAIR256.another(ll,D_bar_l, PAIR256.G1mul(Wprime,e));                        
	FP48 left=PAIR256.fexp(PAIR256.miller(ll));
        
        FP48[] rr=PAIR256.initmp();        
        //1st pairing at right hand side
        temp = PAIR256.G1mul(vprime, _y);
        temp.sub(V);
        PAIR256.another(rr, pk.get_g2x(), temp);
        
        //2nd paring        
        temp = new ECP();
        for(int i=0;i<threshold;i++){
            temp.add(PAIR256.G1mul(barWi[i],_di1[i]));
        }
        temp.sub(Y3);
        PAIR256.another(rr, pk.get_X()[2], temp);
        
        
        //3rd paring
        temp = new ECP();
        
        for(int i=0;i<threshold;i++){
            tempp = new ECP();
            if(i==0){
                tempp.add(pk.get_a0());
            }
            else{
                tempp.add(Di[i-1]);
            }
            tempp.add(PAIR256.G1mul(barWi[i], new BIG(i+1)));
            tempp = PAIR256.G1mul(tempp, _di1[i]);
            tempp.add(PAIR256.G1mul(barWi[i], _di0[i]));
            temp.add(tempp);
        }
        
        tempp = new ECP();
        for(int i=0;i<threshold;i++){
            tempp.add(Ri[i]);
        }
        temp.add(PAIR256.G1mul(tempp, e));
        
        temp.sub(Y4);
        temp.sub(PAIR256.G1mul(R, BIG.modmul(e, new BIG(threshold), order)));
        PAIR256.another(rr, pk.get_X()[1], temp);
        
	FP48 right=PAIR256.fexp(PAIR256.miller(rr));
        
                
        if(left.equals(right)){
            return true;
        }
        else{
            return false;
        }
        }
        catch(NoSuchAlgorithmException e){
            Logger.getLogger(SDHABC.class.getName()).log(Level.SEVERE, null, e);
        } catch (Exception ex) {
            Logger.getLogger(SDHABC.class.getName()).log(Level.SEVERE, null, ex);
            throw new Exception("NANY proof: "+ex.getMessage());            
        }
        
        return false;
    }
    
    
    /**
     * Search for the intersecting attributes.
     * 
     * @param threshold the set intersection threshold.
     * @param A user attribute set.
     * @param Aprime query attribute set.
     * 
     * @throws Exception if the searching for intersecting attributes fails.
     * 
     * @return A' \cup A and the remain A' - A = A' - (A \cup A').
     */
    public ArrayList[] findSame(int threshold, String[] A, String[] Aprime) throws Exception{
        if(threshold<1){
            throw new Exception("Threshold must fall in between 1 <= threshold <= |A'|.");
        }
        if(threshold>Aprime.length){
            throw new Exception("You fail to meet the condition threshold<=|A'|.");
        }
        if(A.length<Aprime.length){
            throw new Exception("You fail to meet the condition |A|>=|A'|.");
        }
        
        ArrayList same = new ArrayList(threshold);    //the intersected set
        ArrayList _A = new ArrayList(A.length);   
        ArrayList _Aprime = new ArrayList(Aprime.length);
        int k=-1,m=0,n=0;
        
        //convert to vector (not yet done: the sequence should be randomized)
        for(int i=0;i<A.length;i++){
            _A.add(A[i]);
        }
        for(int i=0;i<Aprime.length;i++){
            _Aprime.add(Aprime[i]);
        }
        
        for(int i=0;i<Aprime.length;i++){
            k=_A.indexOf(Aprime[i]);
            if(k>-1){   //attr found
                m++;
                same.add(Aprime[i]);
                if(m==threshold){    //not yet enough attr
                    break;
                }                
            }
            else{   //no attr found, do nothing
                
            }
        }
        
        if(m==threshold){
            _Aprime.removeAll(same);
            //_A.removeAll(same);
            //_A.trimToSize();
            same.trimToSize();
            _Aprime.trimToSize();
            
            ArrayList[] result = new ArrayList[2];
            //result[0]=_A;
            result[0]=same;
            result[1]=_Aprime;
            
            return result;
        }
        else{
            throw new Exception("Not enough intersected attributes.");
        }
    }
    
    /**
     * Search for the differing attributes.
     * 
     * @param threshold the set intersection threshold.
     * @param A user attribute set.
     * @param Aprime query attribute set.
     * 
     * @throws Exception if the searching for differing attributes fails.
     * 
     * @return A' - A and the remain A' \cup A = A' - (A' - A).
     */
    public ArrayList[] findNotSame(int threshold, String[] A, String[] Aprime) throws Exception{
        if(threshold<1){
            throw new Exception("Threshold must fall in between 1 <= threshold <= |A'|.");
        }
        if(threshold>Aprime.length){
            throw new Exception("You fail to meet the condition threshold<=|A'|.");
        }
        if(A.length<Aprime.length){
            throw new Exception("You fail to meet the condition |A|>=|A'|.");
        }
        
        ArrayList xsame = new ArrayList(threshold);    //the intersected set
        ArrayList _A = new ArrayList(A.length);   
        ArrayList _Aprime = new ArrayList(Aprime.length);
        int k=-1,m=0,n=0;
        
        //convert to vector (not yet done: the sequence should be randomized)
        for(int i=0;i<A.length;i++){
            _A.add(A[i]);
        }
        for(int i=0;i<Aprime.length;i++){
            _Aprime.add(Aprime[i]);
        }
        
        for(int i=0;i<Aprime.length;i++){
            k=_A.indexOf(Aprime[i]);
            if(k>-1){   //attr found, do nothing                                   
                                        
            }
            else{   //no attr found
                m++;
                xsame.add(Aprime[i]);
                if(m==threshold){
                    break;
                }
            }
        }
        
        if(m==threshold){
            _Aprime.removeAll(xsame);
            xsame.trimToSize();
            _Aprime.trimToSize();
            
            ArrayList[] result = new ArrayList[2];
            result[0]=xsame;
            result[1]=_Aprime;
            
            return result;
        }
        else{
            throw new Exception("Not enough non-intersected attributes.");
        }
    }  
        
    /**
     * Encode monic polynomial roots into coefficients.
     * 
     * @param A attribute set that represent the roots.
     * @param order the elliptic curve (sub-)group order.
     * 
     * @return coefficients of a monic polynomial.
     */
    public BIG[] MPEncode(BIG[] A,BIG order){   
        BIG[] L = new BIG[A.length+1];
        
        for(int i=0;i<L.length;i++){
            L[i] = new BIG();
            L[i].zero();
        }
        
        L[A.length].one();
        
        if(A.length==1){
            L[0] = A[0];
            return L;
        }
        
        L[0] = BIG.modmul(A[0],A[1], order);
        //L[1].zero();
        L[1].add(A[0]);
        L[1].mod(order);
        L[1].add(A[1]);
        L[1].mod(order);
        
        for(int i=2;i<A.length;i++){
            for(int j=i;j>0;j--){
                if(j==i){
                    L[i].add(L[i-1]);
                    L[i].mod(order);
                    L[i].add(A[i]);
                    L[i].mod(order);
                    //L[i]=L[i-1].add(A[i]);                    
                }  
                else if(j==1){ 
                    L[j] = BIG.modmul(L[j], A[i], order);
                    L[j].add(L[j-1]);
                    L[j].mod(order);
                    //L[j] = L[j].multiply(A[i]).add(L[j-1]);
                    
                    L[0] = BIG.modmul(L[0], A[i], order);
                    //L[0] = L[0].multiply(A[i]);
                }
                else{
                    L[j] = BIG.modmul(L[j], A[i], order);
                    L[j].add(L[j-1]);                    
                    L[j].mod(order);
                }
            }
        }
        
        return L;
    }  
    
    /*
    * Old function, buggy where overflow happens in BIG class
    * @return BIG[] with last element BIG[1] as the remainder.
    *
    public BIG[][] syntheticDivisionBIG(BIG[] dvdend, BIG[] dvsor){
        BIG order = new BIG(ROM.CURVE_Order);
        BIG[] ans = new BIG[dvdend.length];        
        for(int i=0;i<dvdend.length;i++){
            ans[i] = new BIG(dvdend[dvdend.length-i-1]);
        }        
        
        BIG[] xdvsor = new BIG[dvsor.length];
        for(int i=0;i<dvsor.length;i++){
            xdvsor[i] = new BIG(dvsor[dvsor.length-i-1]);
        }                
        
        BIG normalizer = new BIG(xdvsor[0]);
        normalizer.invmodp(order);
        for (int i = 0; i < dvdend.length - (dvsor.length - 1); i++) {            
            ans[i]=BIG.modmul(ans[i], normalizer, order);            
            
            BIG coef = new BIG(ans[i]);
            
            if (!coef.iszilch()) {
                for (int j = 1; j < dvsor.length; j++){
                    ans[i+j].sub(BIG.modmul(coef, xdvsor[j], order));
                    ans[i+j].mod(order);
                }
                    //ans[i + j] += -divisor[j] * coef;
            }
        }
        
        int separator = ans.length - (dvsor.length - 1);
        BIG[] temp1 = Arrays.copyOfRange(ans, 0, separator);
        BIG[] temp2 = Arrays.copyOfRange(ans, separator, ans.length);
        
        ans = new BIG[temp1.length];
        for(int i=0;i<temp1.length;i++){
            ans[i] = temp1[temp1.length-i-1];
        }
        
        xdvsor = new BIG[temp2.length];
        for(int i=0;i<temp2.length;i++){
            xdvsor[i] = temp2[temp2.length-i-1];
        } 
        
        return new BIG[][]{
            ans, xdvsor
        };
    }
    */
    
    /**
     * Synthetic division algorithm for polynomial division.
     * 
     * @param dvdend coefficients of dividend.
     * @param dvsor coefficients of divisor.
     * 
     * @return first element BIG[0] as coefficients of quotient and the last element BIG[1] as coefficients of remainder.
     */
    public BIG[][] syntheticDivision(BIG[] dvdend, BIG[] dvsor){
        //BIG order = new BIG(ROM.CURVE_Order);
        BigInteger order = toBigInteger(new BIG(ROM.CURVE_Order));        
        
        //BIG[] ans = new BIG[dvdend.length];        
        BigInteger[] ans = new BigInteger[dvdend.length];
        
        for(int i=0;i<dvdend.length;i++){            
            ans[i] = toBigInteger(dvdend[dvdend.length-i-1]);
        }        
        
        //BIG[] xdvsor = new BIG[dvsor.length];
        BigInteger[] xdvsor = new BigInteger[dvsor.length];
        for(int i=0;i<dvsor.length;i++){            
            xdvsor[i] = toBigInteger(dvsor[dvsor.length-i-1]);
        }                
        
        //BIG normalizer = new BIG(xdvsor[0]);
        
        BigInteger normalizer = xdvsor[0].modInverse(order);
        //normalizer.invmodp(order);
        
        for (int i = 0; i < dvdend.length - (dvsor.length - 1); i++) {            
            //ans[i]=BIG.modmul(ans[i], normalizer, order);            
            ans[i]=ans[i].multiply(normalizer).mod(order);
            
            //BIG coef = new BIG(ans[i]);
            BigInteger coef = ans[i];
            
            //if (!coef.iszilch()) {
            if (!coef.equals(BigInteger.ZERO)) {
                for (int j = 1; j < dvsor.length; j++){
                    //ans[i+j].sub(BIG.modmul(coef, xdvsor[j], order));
                    ans[i+j] = ans[i+j].subtract(coef.multiply(xdvsor[j]).mod(order)).mod(order);
                    //ans[i+j].mod(order);
                }
            }
        }
        
        int separator = ans.length - (dvsor.length - 1);
        //BIG[] temp1 = Arrays.copyOfRange(ans, 0, separator);
        BigInteger[] temp1 = Arrays.copyOfRange(ans, 0, separator);
        //BIG[] temp2 = Arrays.copyOfRange(ans, separator, ans.length);
        BigInteger[] temp2 = Arrays.copyOfRange(ans, separator, ans.length);
        
        //ans = new BIG[temp1.length];
        BIG[] answer = new BIG[temp1.length];
        for(int i=0;i<temp1.length;i++){
            answer[i] = toBIG(temp1[temp1.length-i-1]);
            //ans[i] = temp1[temp1.length-i-1];
        }
        
        BIG[] remainder = new BIG[temp2.length];
        //xdvsor = new BIG[temp2.length];
        for(int i=0;i<temp2.length;i++){
            remainder[i] = toBIG(temp2[temp2.length-i-1]);
            //xdvsor[i] = temp2[temp2.length-i-1];
        } 
        
        return new BIG[][]{
            //ans, xdvsor
            answer, remainder
        };
    }
    
    /**
     * Convert a number in BIG datatype to a number in BigInteger datatype.
     * 
     * @param num the number in BIG to be converted.
     * 
     * @return the number in BigInteger.
     */
    public BigInteger toBigInteger(BIG num){
        byte[] b = new byte[CONFIG_BIG.MODBYTES];
        num.toBytes(b);
        return new BigInteger(b);
    }
    
    /**
     * Convert a number in BigInteger datatype to a number in BIG.
     * 
     * @param num the number in BigInteger to be converted.
     * 
     * @return the number in BIG.
     */
    public BIG toBIG(BigInteger num){
        byte[] b = new byte[CONFIG_BIG.MODBYTES];        
        byte[] val = num.toByteArray();
        
        int j=val.length-1;
        for(int i=b.length-1;i>=0;i--){
            if(j>-1){
                b[i] = val[j];
                j--;
            }else{
                if(num.signum()==-1){
                    b[i] = (byte) 0xff;
                }else{
                    b[i] = (byte) 0x00;
                }
            }
        }
        
        return BIG.fromBytes(b);
    }
    
    
    
}

