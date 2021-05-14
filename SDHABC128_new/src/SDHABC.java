
import java.math.BigInteger;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;
import org.apache.milagro.amcl.BLS461.*;
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
    /*
    public SDHABC(){
        //gen parameter u for BLS12
        //77 bits u: no subG-secure: -1FFFFFFBFFFE00000000 [AMCL]
        //78 bits u: -2080ffffffd7ffc00020 [BD19], no subG-secure: 3024e1144080861734f0
        //79 bits u:         
        BigInteger u,r,p;
        BigInteger _2 = BigInteger.valueOf(2);
        int i=0,bitone=0;
        
        do{
            do{
                u = new BigInteger(80,new SecureRandom());
            }while(u.bitCount()>60 | u.bitLength()<77);
            //u = _2.pow(22).add(_2.pow(35)).add(_2.pow(37)).subtract(_2.pow(5)).subtract(_2.pow(64)).subtract(_2.pow(71)).subtract(_2.pow(77));
            //u = new BigInteger("-1FFFFFFBFFFE00000000",16);
            r = u.pow(4).subtract(u.pow(2)).add(BigInteger.ONE);
            p = u.subtract(BigInteger.ONE).pow(2).divide(BigInteger.valueOf(3)).multiply(r).add(u);            
            i++;
            System.out.println(i);
        }while(!p.mod(BigInteger.valueOf(24)).equals(BigInteger.valueOf(19)) | !r.isProbablePrime(16) | !p.isProbablePrime(16) |               
               !p.pow(4).subtract(p.pow(2)).add(BigInteger.ONE).divide(r).isProbablePrime(16) | //GT subgroup security
               !u.pow(8).subtract(u.pow(7).multiply(BigInteger.valueOf(4))).add(u.pow(6).multiply(BigInteger.valueOf(5))).subtract(u.pow(4).multiply(BigInteger.valueOf(4))).add(u.pow(3).multiply(BigInteger.valueOf(6))).subtract(u.pow(2).multiply(BigInteger.valueOf(4))).subtract(u.multiply(BigInteger.valueOf(4))).add(BigInteger.valueOf(13)).divide(BigInteger.valueOf(9)).isProbablePrime(16)); //G2 subgroup security      
        
        System.out.println("|G2 points|/r is prime? "+u.pow(8).subtract(u.pow(7).multiply(BigInteger.valueOf(4))).add(u.pow(6).multiply(BigInteger.valueOf(5))).subtract(u.pow(4).multiply(BigInteger.valueOf(4))).add(u.pow(3).multiply(BigInteger.valueOf(6))).subtract(u.pow(2).multiply(BigInteger.valueOf(4))).subtract(u.multiply(BigInteger.valueOf(4))).add(BigInteger.valueOf(13)).divide(BigInteger.valueOf(9)).isProbablePrime(16));
        System.out.println("|GT points|/r is prime? "+p.pow(4).subtract(p.pow(2)).add(BigInteger.ONE).divide(r).isProbablePrime(16));
        System.out.println(u.toString(16));        
        System.out.println(u.bitCount());
        System.out.println(u.bitLength());
        System.out.println("u prime? " + u.isProbablePrime(16));        
        System.out.println("u-1 prime? " + u.subtract(BigInteger.ONE).isProbablePrime(16));        
        System.out.println("r prime? " + r.isProbablePrime(16));        
        System.out.println(r.toString(16));
        System.out.println(r.toString());
        System.out.println(r.bitLength());
        System.out.println("p prime? " + p.isProbablePrime(16));
        System.out.println(p.toString(16));   
        System.out.println(p.toString());
        System.out.println(p.bitLength());
        System.out.println("p mod 24 = "+p.mod(BigInteger.valueOf(24)));
    }
    */
    
    public ABCparam Setup(int attrSize){
        RAND RNG = new RAND();
        ECP[] a=new ECP[attrSize];
        ECP2[] X=new ECP2[attrSize];
        ECP a0 = ECP.generator();
        ECP2 g2 = ECP2.generator();        
        
        BIG q=new BIG(ROM.CURVE_Order);
	
        SecureRandom rand = new SecureRandom();
        RNG.clean();
	RNG.seed(100,rand.generateSeed(100));        
        
        BIG x=BIG.randomnum(q,RNG);
        ECP2 g2x = PAIR.G2mul(g2, x);
        
        BIG xprime=BIG.randomnum(q,RNG);
        BIG _1 = new BIG();
        _1.one();
        
        BIG j = new BIG();        
        j.zero();
        
        for(int i=0;i<attrSize;i++){            
            a[i] = PAIR.G1mul(a0, xprime.powmod(j, q));
            X[i] = PAIR.G2mul(g2, xprime.powmod(j, q));
            j.add(_1);
        }
        
        ECP b = PAIR.G1mul(a0,BIG.randomnum(q,RNG));
        ECP c = PAIR.G1mul(a0,BIG.randomnum(q,RNG));
        ABCpk pk = new ABCpk(a0,b,c,a,g2,g2x,X);
        ABCsk sk = new ABCsk(x,xprime);
	//s.toBytes(S);
	//G.toBytes(W);
        
        /*//simple operations benchmark
        long start, total1=0, total2=0, total3=0, total4=0, totalrsa=0;       
        FP12 pair = PAIR.fexp(PAIR.ate(g2,a0));
         
        //for RSA
        BigInteger qq,pp,N,R;
        do{
                qq = new BigInteger(3072/2, 16, rand);
                pp = new BigInteger(3072/2, 16, rand);
                N = pp.multiply(qq);
        }while(!qq.isProbablePrime(16) || !pp.isProbablePrime(16) || N.bitLength()<3072);
        R=new BigInteger(rand.generateSeed(3072/8)).mod(N);
        //end RSA
         
        for(int i=0;i<1000;i++){
            BIG num = BIG.randomnum(q,RNG); 
            BigInteger num1 = toBigInteger(num);
             
            start = System.nanoTime();
            a0=PAIR.G1mul(a0, num);
            total1 += System.nanoTime() - start;
             
            start = System.nanoTime();
            PAIR.G2mul(g2, num);
            total2 += System.nanoTime() - start;
             
            start = System.nanoTime();
            pair.pow(num);
            total3 += System.nanoTime() - start;
             
            start = System.nanoTime();
            PAIR.fexp(PAIR.ate(g2,a0));
            total4 += System.nanoTime() - start;
             
            start = System.nanoTime();
            R.modPow(num1, N);
            totalrsa += System.nanoTime() - start;
        }
        System.out.println("G1 scalar multiplication takes  : "+java.util.concurrent.TimeUnit.MILLISECONDS.convert(total1/1000, java.util.concurrent.TimeUnit.NANOSECONDS)+"ms");
        System.out.println("G2 scalar multiplication takes  : "+java.util.concurrent.TimeUnit.MILLISECONDS.convert(total2/1000, java.util.concurrent.TimeUnit.NANOSECONDS)+"ms");
        System.out.println("GT exponentiation takes         : "+java.util.concurrent.TimeUnit.MILLISECONDS.convert(total3/1000, java.util.concurrent.TimeUnit.NANOSECONDS)+"ms");
        System.out.println("Pairing takes                   : "+java.util.concurrent.TimeUnit.MILLISECONDS.convert(total4/1000, java.util.concurrent.TimeUnit.NANOSECONDS)+"ms");
        System.out.println("RSA modular exponentiation takes: "+java.util.concurrent.TimeUnit.MILLISECONDS.convert(totalrsa/1000, java.util.concurrent.TimeUnit.NANOSECONDS)+"ms");
        //end*/
        
	return new ABCparam(pk, sk);
    }
    
    //contains precomputation MPEncode(A) and MPEncode(A-o) where A={m_1,...,m_n-1,o}
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
            
            //this is for new possession
            //last attribute is the opening value
            BIG[] attrClone = new BIG[attr.length-1];
            
            for(int i=0;i<attr.length;i++){                
                attr[i]= BIG.fromBytes(H.digest(A[i].getBytes()));
                attr[i].mod(order);
                
                //this is for new possession
                if(i<attr.length-1)
                    attrClone[i] = new BIG(attr[i]);
            }
            alphas = MPEncode(attr, order);
            
            //this is for new possession
            BIG[] alphasNoO = MPEncode(attrClone, order);
            
            
            //user chooses random tilde{s,alpha_0,...\alpha_n}
            BIG s1 = BIG.randomnum(order,RNG);
            BIG tildeS = BIG.randomnum(order,RNG);
            BIG[] tildeA = new BIG[alphas.length];
            
            //calculate M,R
            ECP M = PAIR.G1mul(pk.get_b(), s1);
            ECP R = PAIR.G1mul(pk.get_b(), tildeS);
            
            for(int i=0;i<tildeA.length;i++){
                M.add(PAIR.G1mul(pk.get_a()[i], alphas[i]));
                
                tildeA[i] = BIG.randomnum(order,RNG);
                R.add(PAIR.G1mul(pk.get_a()[i], tildeA[i]));
            }
            ECP Mclone = new ECP(M);
            //send M,R to issuer
            
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
            ECP _M = PAIR.G1mul(pk.get_b(), tildeS);
            for(int i=0;i<tildeA.length;i++){
                _M.add(PAIR.G1mul(pk.get_a()[i], tildeA[i]));
            }
            R.add(PAIR.G1mul(M, e));
            
            if(_M.equals(R)){
           
                BIG t = BIG.randomnum(order,RNG);
                BIG s2 = BIG.randomnum(order,RNG);                
                M.add(PAIR.G1mul(pk.get_b(), s2));
                M.add(pk.get_c());
                BIG _t = new BIG(t);
                //_t.copy(t);
                _t.add(sk.get_x());
                _t.invmodp(order);
                ECP v = PAIR.G1mul(M,_t);
                
                //user received credential (t,s2,v)                
                s1.add(s2);     
                s1.mod(order);
                
                //user verifies if this is a valid credential
                ECP temp = PAIR.G1mul(v,t);
                temp.neg();
                
                temp.add(pk.get_c());
                temp.add(PAIR.G1mul(pk.get_b(),s2));
                //if no Mclone
                //temp.add(PAIR.G1mul(pk.get_b(),s1));
                
                temp.add(Mclone);                
                //if no Mclone
                //for(int i=0;i<alphas.length;i++){
                //    temp.add(PAIR.G1mul(pk.get_a()[i],alphas[i]));
                //}
                
                FP12 left=PAIR.fexp(PAIR.ate(pk.get_g2x(),v));
                
                FP12 right=PAIR.fexp(PAIR.ate(pk.get_g2(),temp));
                
                
		if (left.equals(right)){          
                    //this is for old possession
                    //return new ABCcred(t,s1,v,A,alphas);
                    
                    //this is for new possession
                    return new ABCcred(t,s1,v,A,alphas,alphasNoO);
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
    
    //no precomputation MPEncode(A) on attribute set A
    public boolean proofOfPossessionOld(ABCpk pk, ABCcred cred){
        try{
        MessageDigest H = MessageDigest.getInstance("SHA-512");
        RAND RNG = new RAND();
        BIG r,y,_r,_y,_ty,_s,_o0,_o1;
        BIG[] _alpha = new BIG[cred.get_alphas().length];        
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
        
        ECP V1 = PAIR.G1mul(cred.get_v(), BIG.modmul(r, yinv, order));
        ECP V2 = PAIR.G1mul(V1, _y);
        ECP Y = PAIR.G1mul(V1, _ty);        
        Y.add(PAIR.G1mul(pk.get_c(), _r));
        Y.add(PAIR.G1mul(pk.get_b(), _s));
                
        for(int i=0;i<_alpha.length;i++){
            _alpha[i] = BIG.randomnum(order,RNG);
            Y.add(PAIR.G1mul(pk.get_a()[i], _alpha[i]));
        }                                        
        
        //verifier replies a challenge
        BIG e = BIG.randomnum(order,RNG);
        
        //prover sends response
        _r.add(BIG.modmul(e, r, order)); 
        _r.mod(order);
        _y.add(BIG.modmul(e, y, order));        
        _y.mod(order);
        _ty.sub(BIG.modmul(e, BIG.modmul(cred.get_t(), y, order), order));        
        _ty.mod(order);
        _s.add(BIG.modmul(e, BIG.modmul(cred.get_s(),r,order), order));
        _s.mod(order);                
        
            BIG[] attr = new BIG[cred.get_A().length];
            for(int i=0;i<cred.get_A().length;i++){                
                attr[i]= BIG.fromBytes(H.digest(cred.get_A()[i].getBytes()));
                attr[i].mod(order);
            }
            BIG[] alphas = MPEncode(attr, order);
        
        for(int i=0;i<_alpha.length;i++){
            //_alpha[i].add(BIG.modmul(e, BIG.modmul(cred.get_alphas()[i],r,order), order));
            _alpha[i].add(BIG.modmul(e, BIG.modmul(alphas[i],r,order), order));
            _alpha[i].mod(order);
        }
        
        //verifier checks
        ECP temp = PAIR.G1mul(V1, _ty);
        temp.add(PAIR.G1mul(pk.get_c(), _r));
        temp.add(PAIR.G1mul(pk.get_b(), _s));
        for(int i=0;i<_alpha.length;i++){
            temp.add(PAIR.G1mul(pk.get_a()[i], _alpha[i]));            
        }
        temp.sub(Y);
        FP12 left = PAIR.fexp(PAIR.ate(pk.get_g2(), temp));
        
        temp = PAIR.G1mul(V1, _y);
        temp.sub(V2);
        
        //FP12 right2 = PAIR.fexp(PAIR.ate(pk.get_g2x(), temp2));
        
        //right1.mul(right2);
        
        //FP12[] rr=PAIR.initmp();
	//PAIR.another(rr,pk.get_g2(), Y);
	
	FP12 right=PAIR.fexp(PAIR.ate(pk.get_g2x(), temp));
        
        if(left.equals(right))            
            return true;
        else
            return false;
        }
        catch(Exception e){
            Logger.getLogger(SDHABC.class.getName()).log(Level.SEVERE, null, e);
        }
        
        return false;
    }    
    
    //has precomputation MPEncode(A) on attribute set A
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
        
        ECP V1 = PAIR.G1mul(cred.get_v(), BIG.modmul(BIG.modmul(r, r, order), yinv, order));
        ECP V2 = PAIR.G1mul(V1, _y);
        ECP Y1 = PAIR.G1mul(V1, _ty);
        ECP2 Y2 = PAIR.G2mul(pk.get_X()[0], _o0);        
        Y2.add(PAIR.G2mul(pk.get_X()[1], _o1));
        Y1.add(PAIR.G1mul(pk.get_c(), _r));
        Y1.add(PAIR.G1mul(pk.get_b(), _s));
        
        /*
        //This is if using issuing for old possession
        BIG[] w = new BIG[cred.get_A().length-1];
        for(int i=0;i<w.length;i++){
            w[i] = BIG.fromBytes(H.digest(cred.get_A()[i].getBytes()));
            w[i].mod(order);
        }
        w = convertToAlphas(w,order);                                
        
        ECP W = PAIR.G1mul(pk.get_a0(), w[0]);
        for(int i=1;i<w.length;i++){            
            W.add(PAIR.G1mul(pk.get_a()[i], w[i]));
        }
        W = PAIR.G1mul(W, r);
        */
        
        ECP W = PAIR.G1mul(pk.get_a0(), cred.get_alphasNoO()[0]);
        for(int i=1;i<cred.get_alphasNoO().length;i++){            
            W.add(PAIR.G1mul(pk.get_a()[i], cred.get_alphasNoO()[i]));
        }
        W = PAIR.G1mul(W, r);
        
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
        r = BIG.modmul(r, BIG.fromBytes(H.digest(cred.get_A()[cred.get_A().length-1].getBytes())), order);
        _o0.add(BIG.modmul(e, r, order)); 
        _o0.mod(order);        
        //for(int i=0;i<_alpha.length;i++){
        //    _alpha[i].add(BIG.modmul(e, BIG.modmul(cred.get_alphas()[i],r,order), order));
        //    _alpha[i].mod(order);
        //}
        
        //verifier checks
        FP12[] ll=PAIR.initmp();
        ECP2 temp2 = PAIR.G2mul(pk.get_X()[0],_o0);
        temp2.add(PAIR.G2mul(pk.get_X()[1],_o1));
        temp2.sub(Y2);
        PAIR.another(ll, temp2, W);
        
        ECP temp = PAIR.G1mul(V1, _ty);
        temp.add(PAIR.G1mul(pk.get_c(), _r));
        temp.add(PAIR.G1mul(pk.get_b(), _s));
        //for(int i=0;i<_alpha.length;i++){
        //    temp.add(PAIR.G1mul(pk.get_a()[i], _alpha[i]));            
        //}
        temp.sub(Y1);
        //temp.add(PAIR.G1mul(W, e));
        PAIR.another(ll, pk.get_g2(), temp);
        //FP12 left2 = PAIR.fexp(PAIR.ate(pk.get_g2(), temp));
        
        //FP12 right1 = PAIR.fexp(PAIR.ate(pk.get_g2(), Y));
        
        temp = PAIR.G1mul(V1, _y);
        temp.sub(V2);
        
        //FP12 right2 = PAIR.fexp(PAIR.ate(pk.get_g2x(), temp2));
        
        //right1.mul(right2);
        
        //FP12[] rr=PAIR.initmp();
	//PAIR.another(rr,pk.get_g2(), Y);
	
	FP12 right=PAIR.fexp(PAIR.ate(pk.get_g2x(), temp));
        
        if(PAIR.fexp(PAIR.miller(ll)).equals(right))            
            return true;
        else
            return false;
        }
        catch(Exception e){
            Logger.getLogger(SDHABC.class.getName()).log(Level.SEVERE, null, e);
        }
        
        return false;
    }    
    
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
                m[i] = BIG.fromBytes(H.digest(result[0].get(i).getBytes()));
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
        
        ECP Vprime = PAIR.G1mul(cred.get_v(), BIG.modmul(r, yinv, order));
        ECP V = PAIR.G1mul(Vprime, _y);
        
        ECP M = PAIR.G1mul(pk.get_a0(), m[0]);
        for(int i=1;i<m.length;i++){
            M.add(PAIR.G1mul(pk.get_a()[i], m[i]));
        }
        M = PAIR.G1mul(M, r);
        
        ECP Y = PAIR.G1mul(Vprime, _ty);
        Y.add(PAIR.G1mul(pk.get_c(), _r));
        Y.add(PAIR.G1mul(pk.get_b(), _s));        
        
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
        FP12[] ll=PAIR.initmp();	
        
        BIG[] z = new BIG[Aprime.length];
        for(int i=0;i<Aprime.length;i++){
            z[i] = BIG.fromBytes(H.digest(Aprime[i].getBytes()));
            z[i].mod(order);
        }
        z = MPEncode(z, order);
        
        ECP2 temp2 = PAIR.G2mul(pk.get_g2(), z[0]);
        for(int i=1;i<z.length;i++){
            temp2.add(PAIR.G2mul(pk.get_X()[i], z[i]));            
        }
        PAIR.another(ll,temp2, PAIR.G1mul(M, e));
        
        
        ECP temp=PAIR.G1mul(pk.get_b(), _s);
        temp.add(PAIR.G1mul(pk.get_c(), _r));
        temp.add(PAIR.G1mul(Vprime, _ty));        
        temp.sub(Y);
        
	PAIR.another(ll,pk.get_g2(), temp);
	FP12 left=PAIR.fexp(PAIR.miller(ll));
                       
        
        temp = PAIR.G1mul(Vprime, _y);
        temp.sub(V);
       
        
	FP12 right=PAIR.fexp(PAIR.ate(pk.get_g2x(), temp));
        
                
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
            w[i] = BIG.fromBytes(H.digest(result[0].get(i).getBytes()));
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
                barw[i] = BIG.fromBytes(H.digest(result[1].get(i).getBytes()));
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
        
        ECP V1 = PAIR.G1mul(cred.get_v(), BIG.modmul(BIG.modmul(r, r, order), yinv, order));
        ECP V2 = PAIR.G1mul(V1, _y);
        
        ECP M = PAIR.G1mul(pk.get_a0(),m[0]);
        for(int i=1;i<m.length;i++){
            M.add(PAIR.G1mul(pk.get_a()[i], m[i]));
        }
        M = PAIR.G1mul(M, r);
        
        ECP Y1 = PAIR.G1mul(V1, _ty);
        Y1.add(PAIR.G1mul(pk.get_c(), _r));
        Y1.add(PAIR.G1mul(pk.get_b(), _s));        
        
        ECP barW = PAIR.G1mul(pk.get_a0(),barw[0]);
        for(int i=1;i<barw.length;i++){
            barW.add(PAIR.G1mul(pk.get_a()[i], barw[i]));
        }
        BIG rinv = new BIG(r);
        rinv.invmodp(order);
        barW=PAIR.G1mul(barW, rinv);
        
        _omega[0] = BIG.randomnum(order,RNG);
        ECP2 Y2 = PAIR.G2mul(pk.get_g2(),_omega[0]);
        for(int i=1;i<_omega.length;i++){
            _omega[i] = BIG.randomnum(order,RNG);
            Y2.add(PAIR.G2mul(pk.get_X()[i], _omega[i]));
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
        FP12[] ll=PAIR.initmp();	       
        
        ECP2 temp2 = PAIR.G2mul(pk.get_g2(), _omega[0]);        
        for(int i=1;i<_omega.length;i++){
            temp2.add(PAIR.G2mul(pk.get_X()[i], _omega[i]));            
        }
        temp2.sub(Y2);
        barW.add(M);
        PAIR.another(ll,temp2, barW);
        
        BIG[] z = new BIG[Aprime.length];
        for(int i=0;i<Aprime.length;i++){
            z[i] = BIG.fromBytes(H.digest(Aprime[i].getBytes()));  
            z[i].mod(order);
        }
        z = MPEncode(z, order);
        ECP temp=PAIR.G1mul(pk.get_a()[0], z[0]);
        for(int i=1;i<z.length;i++){
            temp.add(PAIR.G1mul(pk.get_a()[i], z[i]));            
        }
        temp=PAIR.G1mul(temp, e);
        temp.neg();
        temp.sub(Y1);
        temp.add(PAIR.G1mul(pk.get_b(), _s));
        temp.add(PAIR.G1mul(pk.get_c(), _r));
        temp.add(PAIR.G1mul(V1, _ty));
        
	PAIR.another(ll,pk.get_g2(), temp);
	FP12 left=PAIR.fexp(PAIR.miller(ll));
                       
        
        temp = PAIR.G1mul(V1, _y);
        temp.sub(V2);
       
        
	FP12 right=PAIR.fexp(PAIR.ate(pk.get_g2x(), temp));
        
                
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
            m[i] = BIG.fromBytes(H.digest(result[0].get(i).getBytes()));
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
        
        ECP vprime = PAIR.G1mul(cred.get_v(), BIG.modmul(r, yinv, order));
        ECP V = PAIR.G1mul(vprime, _y);
                
        ECP W = PAIR.G1mul(pk.get_a0(),w[0]);
        for(int i=1;i<w.length;i++){
            W.add(PAIR.G1mul(pk.get_a()[i], w[i]));
        }
        W = PAIR.G1mul(W, r);
        
        ECP R = PAIR.G1mul(pk.get_a0(),d[0]);
        for(int i=1;i<d.length;i++){
            R.add(PAIR.G1mul(pk.get_a()[i], d[i]));
        }
        R = PAIR.G1mul(R, r);
        
        ECP[] barWi = new ECP[barw.length];
        
        for(int i=0;i<barw.length;i++){
            barWi[i] = PAIR.G1mul(pk.get_a0(),barw[i][0]);
            for(int j=1;j<barw[i].length;j++){
                barWi[i].add(PAIR.G1mul(pk.get_a()[j], barw[i][j]));
            }
            barWi[i] = PAIR.G1mul(barWi[i], r);
        }
        
        
        ECP[] Ri = new ECP[barr.length];
        for(int i=0;i<barr.length;i++){
            Ri[i] = PAIR.G1mul(pk.get_a0(),barr[i]);
            Ri[i] = PAIR.G1mul(Ri[i], r);
        }
                    
        
        ECP Y = PAIR.G1mul(vprime, _ty);
        Y.add(PAIR.G1mul(pk.get_c(), _r));
        Y.add(PAIR.G1mul(pk.get_b(), _s));        
        
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
        FP12[] ll=PAIR.initmp();       
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
        
        ECP temp = PAIR.G1mul(R, BIG.modmul(e, exp, order));
           
        for(int i=0;i<barWi.length;i++){
            temp.sub(PAIR.G1mul(barWi[i], BIG.modmul(e, BIG.modmul(m[i], new BIG(i+1), order), order)));
            temp.sub(PAIR.G1mul(Ri[i], BIG.modmul(e, new BIG(i+1), order)));
        }
        
        temp.add(PAIR.G1mul(pk.get_b(), _s));
        temp.add(PAIR.G1mul(pk.get_c(), _r));
        temp.add(PAIR.G1mul(vprime, _ty));        
        temp.sub(Y);
	PAIR.another(ll,pk.get_g2(), temp);
	
        ECP temp1 = PAIR.G1mul(W, e);        
        
        m = new BIG[Aprime.length];
        for(int i=0;i<Aprime.length;i++){
            m[i] = BIG.fromBytes(H.digest(Aprime[i].getBytes()));
            m[i].mod(order);
        }
        m = MPEncode(m, order);
        
        ECP2 temp2 = PAIR.G2mul(pk.get_g2(), m[0]);
        for(int i=1;i<m.length;i++){
            temp2.add(PAIR.G2mul(pk.get_X()[i], m[i]));            
        }
        
        PAIR.another(ll,temp2, temp1);                        
	FP12 left=PAIR.fexp(PAIR.miller(ll));
                       
        
        temp = PAIR.G1mul(vprime, _y);
        temp.sub(V);
       
        
	FP12 right=PAIR.ate(pk.get_g2x(), temp);
        
        temp = new ECP();
        temp.inf();
        for(int i=0;i<barWi.length;i++){
            temp.add(barWi[i]);
        }
        temp = PAIR.G1mul(temp, e);
        
        right.mul(PAIR.ate(pk.get_X()[2], temp));
        
        temp = new ECP();
        temp.inf();
        m = new BIG[Aprime.length];
        for(int i=0;i<Aprime.length;i++){
            m[i] = BIG.fromBytes(H.digest(Aprime[i].getBytes()));
            m[i].mod(order);
        }
        for(int i=0;i<barWi.length;i++){
            exp = new BIG(m[i]);
            exp.add(new BIG(i+1));
            
            temp.add(PAIR.G1mul(barWi[i], BIG.modmul(e, exp, order)));
            temp.add(PAIR.G1mul(Ri[i], e));
        } 
        temp.sub(PAIR.G1mul(R, BIG.modmul(e, new BIG(Aprime.length), order)));
        
        right.mul(PAIR.ate(pk.get_X()[1],temp));
                
        if(left.equals(PAIR.fexp(right))){
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
    
    
    public boolean proofOfNANY(ABCpk pk, ABCcred cred, int threshold, String[] Aprime) throws Exception{
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
            d[i] = BIG.fromBytes(H.digest(result[0].get(i).getBytes()));
            d[i].mod(order);
        }
        d = MPEncode(d, order);
        
        //compute witness D_\bar{l} for the divisor D
        ECP2 D_bar_l = new ECP2();
        for(int i=0;i<d.length;i++){
            D_bar_l.add(PAIR.G2mul(pk.get_X()[i], d[i]));
        }
        
        //those remaining attributes in A', i.e., A'-D, can be mixture of same and not same
        BIG[] m2 = new BIG[result[1].size()];
        for(int i=0;i<m2.length;i++){            
            m2[i] = BIG.fromBytes(H.digest(result[1].get(i).getBytes()));
            m2[i].mod(order);
        }
        m2 = MPEncode(m2, order);
        
        //compute witness W' for A'-D
        ECP Wprime = PAIR.G1mul(pk.get_a0(),m2[0]);
        for(int i=1;i<m2.length;i++){
            Wprime.add(PAIR.G1mul(pk.get_a()[i], m2[i]));
        }
        
        BIG[][] division = syntheticDivision(cred.get_alphas(),d);
        w = division[0]; //quotient
        mathsf_r = division[1]; //remainder
                     
        //compute witness W for quotient
        ECP W = new ECP();
        for(int i=0;i<w.length;i++){
            W.add(PAIR.G1mul(pk.get_a()[i], w[i]));
        }
        
        //compute witness R for remainder
        ECP R = new ECP();
        for(int i=0;i<mathsf_r.length;i++){
            R.add(PAIR.G1mul(pk.get_a()[i], mathsf_r[i]));            
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
        
        ECP vprime = PAIR.G1mul(cred.get_v(), BIG.modmul(r.powmod(new BIG(threshold+1), order), yinv, order));
        ECP V = PAIR.G1mul(vprime, _y);
        
        //randomize the witnesses
        W = PAIR.G1mul(W, r);
        R = PAIR.G1mul(R, r.powmod(new BIG(threshold+1), order));
        
        BIG rinv = r.powmod(new BIG(threshold), order);
        rinv.invmodp(order);
        Wprime = PAIR.G1mul(Wprime, rinv);
                
        D_bar_l = PAIR.G2mul(D_bar_l, r.powmod(new BIG(threshold), order));
        
        
        //compute witnesses D_i and its bar{W}_i, R_i for R=bar{W}_i^{x'+d_j}R_i       
        d = new BIG[result[0].size()];//result[0].size() equals to threshold
        ECP[] Di = new ECP[d.length-1];
        ECP[] barWi = new ECP[d.length];
        ECP[] Ri = new ECP[d.length];
        for(int i=0;i<d.length;i++){            
            d[i] = BIG.fromBytes(H.digest(result[0].get(i).getBytes()));
            d[i].mod(order);
            
            BIG[] tmp = new BIG[i+1];
            for(int j=0;j<i+1;j++){
                tmp[j] = new BIG(d[j]);
            }
            tmp = MPEncode(tmp, order);
            
            if(i<Di.length){
                Di[i] = new ECP();
                for(int j=0;j<tmp.length;j++){
                    Di[i].add(PAIR.G1mul(pk.get_a()[j], tmp[j]));
                }
                Di[i] = PAIR.G1mul(Di[i], r.powmod(new BIG(i+1), order));
            }
            tmp = new BIG[1];
            tmp[0] = new BIG(d[i]);            
            BIG[][] div = syntheticDivision(mathsf_r,MPEncode(tmp,order));
            BIG[] barw = div[0]; //quotient
            BIG[] barmathsf_r = div[1]; //remainder
            
            barWi[i] = new ECP();
            for(int j=0;j<barw.length;j++){
                barWi[i].add(PAIR.G1mul(pk.get_a()[j], barw[j]));
            }
            barWi[i] = PAIR.G1mul(barWi[i], r.powmod(new BIG(threshold), order));
            
            Ri[i] = PAIR.G1mul(pk.get_a0(), BIG.modmul(barmathsf_r[0],r.powmod(new BIG(threshold+1), order), order));            
        }
                        
        ECP Y1 = PAIR.G1mul(vprime, _ty);
        Y1.add(PAIR.G1mul(pk.get_c(), _r));
        Y1.add(PAIR.G1mul(pk.get_b(), _s));
                
        ECP Y2 = new ECP();
        for(int i=0;i<threshold;i++){
            ECP temp = new ECP();
            if(i==0){
                temp.add(pk.get_a0());
            }
            else{
                temp.add(Di[i-1]);
            }
            temp.add(PAIR.G1mul(barWi[i], new BIG(i+1)));
            temp.neg();
            temp = PAIR.G1mul(temp, _di0[i]);
            Y2.add(temp);
        }
        
        ECP Y3 = new ECP();
        for(int i=0;i<threshold;i++){
            Y3.add(PAIR.G1mul(barWi[i], _di1[i]));
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
            temp.add(PAIR.G1mul(barWi[i], new BIG(i+1)));
            temp = PAIR.G1mul(temp, _di1[i]);
            temp.add(PAIR.G1mul(barWi[i], _di0[i]));
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
        FP12[] ll=PAIR.initmp();
        ECP temp = new ECP();
        
        //compute R^{e(1+sum_i=1^\bar{l} i)}
        int num = 1;
        for(int i=0;i<threshold;i++){
            num += i+1;
        }
        temp.add(PAIR.G1mul(R, BIG.modmul(e, new BIG(num), order)));
        
        temp.add(PAIR.G1mul(pk.get_b(), _s));
        temp.add(PAIR.G1mul(pk.get_c(), _r));
        temp.add(PAIR.G1mul(vprime, _ty));        
        temp.sub(Y1);
        
        BIG[] m1 = new BIG[Aprime.length];
        for(int i=0;i<Aprime.length;i++){
            m1[i] = BIG.fromBytes(H.digest(Aprime[i].getBytes()));
            m1[i].mod(order);
        }
        m1 = MPEncode(m1, order);
        
        ECP tempp = new ECP();
        for(int i=0;i<m1.length;i++){
            tempp.add(PAIR.G1mul(pk.get_a()[i], m1[i]));            
        }
        temp.sub(PAIR.G1mul(tempp, e));
        
        tempp = new ECP();
        for(int i=0;i<Di.length;i++){
            tempp.add(Di[i]);
        }
        temp.add(PAIR.G1mul(tempp, e));
        
        for(int i=0;i<threshold;i++){
            tempp = new ECP();
            if(i==0){
                tempp.add(pk.get_a0());
            }
            else{
                tempp.add(Di[i-1]);
            }
            tempp.add(PAIR.G1mul(barWi[i], new BIG(i+1)));
            tempp.neg();
            tempp = PAIR.G1mul(tempp, _di0[i]);
            temp.add(tempp);
        }        
        temp.sub(Y2);
        
        
        tempp = new ECP();
        for(int i=0;i<threshold;i++){
            tempp.add(PAIR.G1mul(Ri[i], new BIG(i+1)));
        }
        temp.sub(PAIR.G1mul(tempp, e));
                
	PAIR.another(ll,pk.get_g2(), temp);
	
        
        //1st pairing at left hand side
        Wprime.add(W);  
        Wprime.add(pk.get_a0());
        PAIR.another(ll,D_bar_l, PAIR.G1mul(Wprime,e));                        
	FP12 left=PAIR.fexp(PAIR.miller(ll));
        
        FP12[] rr=PAIR.initmp();        
        //1st pairing at right hand side
        temp = PAIR.G1mul(vprime, _y);
        temp.sub(V);
        PAIR.another(rr, pk.get_g2x(), temp);
        
        //2nd paring        
        temp = new ECP();
        for(int i=0;i<threshold;i++){
            temp.add(PAIR.G1mul(barWi[i],_di1[i]));
        }
        temp.sub(Y3);
        PAIR.another(rr, pk.get_X()[2], temp);
        
        
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
            tempp.add(PAIR.G1mul(barWi[i], new BIG(i+1)));
            tempp = PAIR.G1mul(tempp, _di1[i]);
            tempp.add(PAIR.G1mul(barWi[i], _di0[i]));
            temp.add(tempp);
        }
        
        tempp = new ECP();
        for(int i=0;i<threshold;i++){
            tempp.add(Ri[i]);
        }
        temp.add(PAIR.G1mul(tempp, e));
        
        temp.sub(Y4);
        temp.sub(PAIR.G1mul(R, BIG.modmul(e, new BIG(threshold), order)));
        PAIR.another(rr, pk.get_X()[1], temp);
        
	FP12 right=PAIR.fexp(PAIR.miller(rr));
        
                
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
    
    
    //Flawed, does not check whether divisor and remainder has common monic divisor
    public boolean flawedproofOfNAND(ABCpk pk, ABCcred cred, String[] Aprime) throws Exception{
        try{
        MessageDigest H = MessageDigest.getInstance("SHA-512");
        RAND RNG = new RAND();
        BIG r,y,_r,_y,_ty,_s;        
        BIG order = new BIG(ROM.CURVE_Order);
        BIG[] m, d;
        
        //if threshold doesn't met, exception thrown
        //so, we don't need to perform a check anymore
        ArrayList<String>[] result = findNotSame(Aprime.length,cred.get_A(),Aprime);                
                
        //those not-same attributes        
        BIG[] z = new BIG[result[0].size()];
        for(int i=0;i<z.length;i++){            
            z[i] = BIG.fromBytes(H.digest(result[0].get(i).getBytes()));
            z[i].mod(order);
        }
                
        BIG[][] division = syntheticDivision(cred.get_alphas(),
                                             MPEncode(z, order));
        m = division[0]; //answer
        d = division[1]; //remainder
          
        SecureRandom rand = new SecureRandom();
        RNG.clean();
	RNG.seed(100,rand.generateSeed(100));
        
        BIG[] _d = new BIG[d.length];
        
        r = BIG.randomnum(order,RNG);
        y = BIG.randomnum(order,RNG);
        BIG yinv=new BIG(y);
        yinv.invmodp(order);
        _r = BIG.randomnum(order,RNG);
        _y = BIG.randomnum(order,RNG);
        _ty = BIG.randomnum(order,RNG);
        _s = BIG.randomnum(order,RNG);
        
        ECP V1 = PAIR.G1mul(cred.get_v(), BIG.modmul(r, yinv, order));
        ECP V2 = PAIR.G1mul(V1, _y);
        
        _d[0] = BIG.randomnum(order,RNG);
        ECP D = PAIR.G1mul(pk.get_a0(),_d[0]);
        for(int i=1;i<_d.length;i++){
            _d[i] = BIG.randomnum(order,RNG);
            D.add(PAIR.G1mul(pk.get_a()[i], _d[i]));
        }
        
        ECP M = PAIR.G1mul(pk.get_a0(),m[0]);
        for(int i=1;i<m.length;i++){
            M.add(PAIR.G1mul(pk.get_a()[i], m[i]));
        }
        M = PAIR.G1mul(M, r);
        
        ECP Y = PAIR.G1mul(V1, _ty);
        Y.add(PAIR.G1mul(pk.get_c(), _r));
        Y.add(PAIR.G1mul(pk.get_b(), _s));        
        
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
        
        for(int i=0;i<_d.length;i++){
            _d[i].add(BIG.modmul(e, BIG.modmul(d[i],r,order), order));
            _d[i].mod(order);
        }
        
        //verifier checks        
        //new checking, only 3 pairings
        ECP temp = PAIR.G1mul(pk.get_a0(), _d[0]);
        for(int i=1;i<_d.length;i++){
            temp.add(PAIR.G1mul(pk.get_a()[i], _d[i]));            
        }
        temp.sub(D);
        
        if(temp.is_infinity()){
            return false;
        }
        
        FP12[] ll=PAIR.initmp();
        temp.add(PAIR.G1mul(pk.get_b(), _s));
        temp.add(PAIR.G1mul(pk.get_c(), _r));
        temp.add(PAIR.G1mul(V1, _ty));        
        temp.sub(Y);
	PAIR.another(ll,pk.get_g2(), temp);
	
        ECP temp1 = PAIR.G1mul(M, e);        
        
        z = new BIG[Aprime.length];
        for(int i=0;i<Aprime.length;i++){
            z[i] = BIG.fromBytes(H.digest(Aprime[i].getBytes()));
            z[i].mod(order);
        }
        z = MPEncode(z, order);
        
        ECP2 temp2 = PAIR.G2mul(pk.get_g2(), z[0]);
        for(int i=1;i<z.length;i++){
            temp2.add(PAIR.G2mul(pk.get_X()[i], z[i]));            
        }
        
        PAIR.another(ll,temp2, temp1);                        
	FP12 left=PAIR.fexp(PAIR.miller(ll));
                       
        
        temp = PAIR.G1mul(V1, _y);
        temp.sub(V2);
       
        
	FP12 right=PAIR.fexp(PAIR.ate(pk.get_g2x(), temp));
        
                
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
            throw new Exception("NAND proof: "+ex.getMessage());            
        }
        
        return false;
    }
    
    
    //Flawed, does not check whether divisor and remainder has common monic divisor
    public boolean flawedproofOfNANY(ABCpk pk, ABCcred cred, int threshold, String[] Aprime) throws Exception{
        try{
        MessageDigest H = MessageDigest.getInstance("SHA-512");
        RAND RNG = new RAND();
        BIG r,y,_r,_y,_ty,_s;        
        BIG order = new BIG(ROM.CURVE_Order);
        BIG[] m, d;
        
        //if threshold doesn't met, exception thrown
        //so, we don't need to perform a check anymore
        ArrayList<String>[] result = findNotSame(threshold,cred.get_A(),Aprime);                
                
        //those not-same attributes        
        BIG[] barw = new BIG[result[0].size()];
        for(int i=0;i<barw.length;i++){            
            barw[i] = BIG.fromBytes(H.digest(result[0].get(i).getBytes()));
            barw[i].mod(order);
        }
        barw = MPEncode(barw, order);
        
        //those remaining attributes in A', can be mixture of same and not same
        BIG[] w = new BIG[result[1].size()];
        for(int i=0;i<w.length;i++){            
            w[i] = BIG.fromBytes(H.digest(result[1].get(i).getBytes()));
            w[i].mod(order);
        }
        w = MPEncode(w, order);
                
        BIG[][] division = syntheticDivision(cred.get_alphas(),
                                             barw);
        m = division[0]; //answer
        d = division[1]; //remainder
        
                
        SecureRandom rand = new SecureRandom();
        RNG.clean();
	RNG.seed(100,rand.generateSeed(100));
        
        BIG[] _d = new BIG[d.length];
        BIG[] _barw = new BIG[barw.length];
        
        r = BIG.randomnum(order,RNG);
        y = BIG.randomnum(order,RNG);
        BIG yinv=new BIG(y);
        yinv.invmodp(order);
        _r = BIG.randomnum(order,RNG);
        _y = BIG.randomnum(order,RNG);
        _ty = BIG.randomnum(order,RNG);
        _s = BIG.randomnum(order,RNG);
        
        ECP V1 = PAIR.G1mul(cred.get_v(), BIG.modmul(BIG.modmul(r,r,order), yinv, order));
        ECP V2 = PAIR.G1mul(V1, _y);
        
        
        ECP M = PAIR.G1mul(pk.get_a0(),m[0]);
        for(int i=1;i<m.length;i++){
            M.add(PAIR.G1mul(pk.get_a()[i], m[i]));
        }
        M = PAIR.G1mul(M, r);
        
        ECP W = PAIR.G1mul(pk.get_a0(),w[0]);
        for(int i=1;i<w.length;i++){
            W.add(PAIR.G1mul(pk.get_a()[i], w[i]));
        }
        BIG rinv = new BIG(r);
        rinv.invmodp(order);
        W = PAIR.G1mul(W, rinv);
        
        _d[0] = BIG.randomnum(order,RNG);
        ECP D = PAIR.G1mul(pk.get_a0(),_d[0]);
        for(int i=1;i<_d.length;i++){
            _d[i] = BIG.randomnum(order,RNG);
            D.add(PAIR.G1mul(pk.get_a()[i], _d[i]));
        }
        
        _barw[0] = BIG.randomnum(order,RNG);
        ECP2 Y2 = PAIR.G2mul(pk.get_X()[0],_barw[0]);
        for(int i=1;i<_barw.length;i++){
            _barw[i] = BIG.randomnum(order,RNG);
            Y2.add(PAIR.G2mul(pk.get_X()[i], _barw[i]));
        }
                
        ECP Y1 = PAIR.G1mul(V1, _ty);
        Y1.add(PAIR.G1mul(pk.get_c(), _r));
        Y1.add(PAIR.G1mul(pk.get_b(), _s));        
        
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
            
        
        for(int i=0;i<_barw.length;i++){
            _barw[i].add(BIG.modmul(e, BIG.modmul(barw[i],r,order), order));
            _barw[i].mod(order);
        }
        
        for(int i=0;i<_d.length;i++){
            _d[i].add(BIG.modmul(e, BIG.modmul(d[i],BIG.modmul(r,r,order),order), order));
            _d[i].mod(order);
        }
        
        //verifier checks        
        //new checking, only 3 pairings
        ECP temp = PAIR.G1mul(pk.get_a0(), _d[0]);
        for(int i=1;i<_d.length;i++){
            temp.add(PAIR.G1mul(pk.get_a()[i], _d[i]));            
        }
        temp.sub(D);
        
        if(temp.is_infinity()){
            return false;
        }
        
        FP12[] ll=PAIR.initmp();
        temp.add(PAIR.G1mul(pk.get_b(), _s));
        temp.add(PAIR.G1mul(pk.get_c(), _r));
        temp.add(PAIR.G1mul(V1, _ty));        
        temp.sub(Y1);
        
        
        BIG[] z = new BIG[Aprime.length];
        for(int i=0;i<Aprime.length;i++){
            z[i] = BIG.fromBytes(H.digest(Aprime[i].getBytes()));
            z[i].mod(order);
        }
        z = MPEncode(z, order);
        
        ECP tempp = PAIR.G1mul(pk.get_a0(), z[0]);
        for(int i=1;i<z.length;i++){
            tempp.add(PAIR.G1mul(pk.get_a()[i], z[i]));            
        }
        temp.sub(PAIR.G1mul(tempp, e));
        
	PAIR.another(ll,pk.get_g2(), temp);
	
        
        ECP2 temp2=PAIR.G2mul(pk.get_g2(), _barw[0]);        
        for(int i=1;i<_barw.length;i++){
            temp2.add(PAIR.G2mul(pk.get_X()[i], _barw[i]));            
        }
        temp2.sub(Y2);
        
        W.add(M);
        PAIR.another(ll,temp2, W);                        
	FP12 left=PAIR.fexp(PAIR.miller(ll));
                       
        
        temp = PAIR.G1mul(V1, _y);
        temp.sub(V2);
       
        
	FP12 right=PAIR.fexp(PAIR.ate(pk.get_g2x(), temp));
        
                
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
    
    /*
    * @return BIG[] with last element BIG[1] as the remainder.
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
    
    public BigInteger toBigInteger(BIG num){
        byte[] b = new byte[CONFIG_BIG.MODBYTES];
        num.toBytes(b);
        return new BigInteger(b);
        //return new BigInteger(num.toString().replaceFirst("^0+(?!$)", ""),16);
    }
    
    public BIG toBIG(BigInteger num){//116 hex char, 512 bits, 64 bytes
//        String str = num.toString(16);
//        String prefix="";
//        if(str.length()<116){
//            
//            for(int i=0;i<116-str.length();i++){
//                prefix+="0";
//            }
//            prefix+=str;
//        }
//        
//        byte[] val = new byte[prefix.length() / 2];
//        for (int i = 0; i < val.length; i++) {
//            int index = i * 2;
//            int j = Integer.parseInt(prefix.substring(index, index + 2), 16);
//            val[i] = (byte) j;
//        }
//        return BIG.fromBytes(val);
        
        
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
    
    /*
    public int rho(String[] A, String attr){
        
        for(int i=0;i<A.length;i++){
            if(A[i].equals(attr)){
                return i;
            }
        }
        
        return -1;
    }
    
    public String[][] findSameXsame(boolean SAME, int threshold, String[] A, String[] Aprime){
        String[] same;
        String[] xsame;
        String temp ="!";
        String xtemp ="!";
        int length = A.length;
        int k=-1,j=0,i=0;
                
        if(Aprime.length>=length){
            length = Aprime.length;
            while(i<length){
                k=rho(A,Aprime[i]);
                if(SAME){
                if(k>-1 && j<threshold){
                    j++;
                    temp=temp.concat(","+A[k]);     
                    
                }
                else if(k>-1 && j>=threshold){
                    xtemp = xtemp.concat(","+Aprime[i]);
                }
                else{
                    xtemp = xtemp.concat(","+Aprime[i]);
                }
                }
                else{
                    if(k==-1 && j<threshold){
                    j++;
                    temp=temp.concat(","+Aprime[i]);     
                    
                    }
                    else if(k==-1 && j>=threshold){
                    xtemp = xtemp.concat(","+Aprime[i]);
                    }
                    else{
                    xtemp = xtemp.concat(","+A[k]);
                    }
                }
                i++;
            }
        }
        else{
            length = Aprime.length;
            while(i<length){
                k=rho(Aprime,A[i]);
                
                if(SAME){
                if(k>-1 && j<threshold){
                    j++;
                    temp=temp.concat(","+A[k]);
                }
                else if(k>-1 && j>=threshold){
                    xtemp = xtemp.concat(","+Aprime[i]);
                }
                else{
                    xtemp = xtemp.concat(","+Aprime[i]);
                }
                }
                else{
                    if(k==-1 && j<threshold){
                    j++;
                    temp=temp.concat(","+Aprime[i]);     
                    
                    }
                    else if(k==-1 && j>=threshold){
                    xtemp = xtemp.concat(","+Aprime[i]);
                    }
                    else{
                    xtemp = xtemp.concat(","+A[k]);
                    }
                }
                i++;
            }
        }
        
        if(j==threshold){
            //System.out.println("threshold met, temp: "+temp+", xtemp: "+xtemp);
            temp.trim();
            temp = temp.split("!")[1];
            String[] tt = temp.split(",");
            same = new String[tt.length-1]; 
            for(i=1;i<tt.length;i++){                        
                same[i-1]=tt[i];            
            }
        
            if(xtemp.length()>1){
                xtemp.trim();
                xtemp = xtemp.split("!")[1];
                tt = xtemp.split(",");
                xsame = new String[tt.length-1]; 
                for(i=1;i<tt.length;i++){                        
                    xsame[i-1]=tt[i];            
                }
            }
            else{
                xsame=null;
            }
            String[][] result = new String[2][];
            result[0]=same;
            result[1]=xsame;
            return result;
        }
        else{
            //System.out.println("threshold="+threshold+", j="+j+", threshold not met:"+temp);
            return null;
        }
    }
    */  
    
}

