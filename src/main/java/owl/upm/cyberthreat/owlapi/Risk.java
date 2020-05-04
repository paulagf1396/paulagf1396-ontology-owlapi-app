package owl.upm.cyberthreat.owlapi;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import org.semanticweb.owlapi.model.IRI;
import org.semanticweb.owlapi.model.OWLClass;
import org.semanticweb.owlapi.model.OWLClassAssertionAxiom;
import org.semanticweb.owlapi.model.OWLClassExpression;
import org.semanticweb.owlapi.model.OWLDataFactory;
import org.semanticweb.owlapi.model.OWLDataProperty;
import org.semanticweb.owlapi.model.OWLDataPropertyAssertionAxiom;
import org.semanticweb.owlapi.model.OWLIndividual;
import org.semanticweb.owlapi.model.OWLLiteral;
import org.semanticweb.owlapi.model.OWLNamedIndividual;
import org.semanticweb.owlapi.model.OWLOntology;
import org.semanticweb.owlapi.model.OWLOntologyManager;
import org.semanticweb.owlapi.model.PrefixManager;
import org.semanticweb.owlapi.reasoner.NodeSet;
import org.semanticweb.owlapi.reasoner.OWLReasoner;
import org.semanticweb.owlapi.util.DefaultPrefixManager;

public class Risk {

	
	Map<String, Float> rr = new HashMap<String, Float>();
	Map<String, Float> pr = new HashMap<String, Float>();
	
	
	public String obtainDataPropertyValue(OWLIndividual individual,OWLDataProperty dproperty, OWLOntology o, OWLReasoner reasoner) {
        //System.out.println("obtenerValorPropiedadData");
        //System.out.println(" individuoS: "+individuoS+", propiedadS: "+propiedadS);
        
		
        String result = null;
   
        Set<OWLDataPropertyAssertionAxiom> properties = o.getDataPropertyAssertionAxioms(individual);
			for (OWLDataPropertyAssertionAxiom ax : properties) {
				if (ax.getProperty().equals(dproperty) && ax.getSubject().equals(individual)) {
			             result = ax.getObject().getLiteral().toString();
			         }
			}
        return(result);
    }

	public boolean isResidualRisk(OWLIndividual individual, OWLOntology o, OWLDataFactory dataFactory, OWLReasoner reasoner, String base_DRM) {
		PrefixManager pmDRM = new DefaultPrefixManager(base_DRM + "#");
		
        boolean result = false;
        OWLClassExpression rr = dataFactory.getOWLClass(":ResidualRisk", pmDRM);

        Set<OWLClassAssertionAxiom> classes = o.getClassAssertionAxioms(individual);
			for (OWLClassAssertionAxiom ax : classes) {
				if (ax.getClassExpression().equals(rr)) {
			             result = true;
			         }
			}
      
		return result;
	}
	
	public boolean isPotentialRisk(OWLIndividual individual, OWLOntology o, OWLDataFactory dataFactory, OWLReasoner reasoner, String base_DRM) {
		PrefixManager pmDRM = new DefaultPrefixManager(base_DRM + "#");
		
        boolean result = false;
        OWLClassExpression pr = dataFactory.getOWLClass(":PotentialRisk", pmDRM);

        Set<OWLClassAssertionAxiom> classes = o.getClassAssertionAxioms(individual);
			for (OWLClassAssertionAxiom ax : classes) {
				if (ax.getClassExpression().equals(pr)) {
			             result = true;
			         }
			}
      
		return result;
	}
	
	/*************************************************************/
    /**                                                         **/
    /**              Dynamic Risk Calculation                   **/
    /**                                                         **/
    /*************************************************************/
	
	public Map<String, Float> residualRiskCalculation(OWLOntology o, OWLOntologyManager man, OWLDataFactory dataFactory, String base, OWLReasoner reasoner, String base_DRM) {
		PrefixManager pmDRM = new DefaultPrefixManager(base_DRM + "#");
		PrefixManager pm = new DefaultPrefixManager(base + "#");

		Map<String, Float> residualRiskValues = new HashMap<String, Float>();
		float residualRiskTotalValue = 0 ;
		int n=0;
		
		
		OWLClassExpression rr = dataFactory.getOWLClass(":ResidualRisk", pmDRM);
		System.out.println("La clase rr es: "+rr);
	
		Set<OWLNamedIndividual> setInstances = o.getIndividualsInSignature();
        for (OWLNamedIndividual i : setInstances) {
            
            if(isResidualRisk(i, o, dataFactory, reasoner, base_DRM)) {
            	 OWLDataProperty aRisk = dataFactory.getOWLDataProperty(":actualRisk", pm);
            	 OWLDataProperty ptype = dataFactory.getOWLDataProperty(":type", pm);
                 
                 //Valor de la propiedad actualRisk (7.0)
             
         	    String s = obtainDataPropertyValue(i, aRisk, o, reasoner);
         	    if(!s.isEmpty()) {
         		   float d_float = Float.parseFloat(s);
             	   residualRiskTotalValue = residualRiskTotalValue + d_float;
             	   System.out.println(residualRiskTotalValue);
             	   String type = obtainDataPropertyValue(i, ptype, o, reasoner);
             	   residualRiskValues.put(type, d_float);
             	   System.out.println(type);
         	    }
         	    n++;
    			

            }     
        }
            
        
        System.out.println("The residual risk total value is : "+residualRiskTotalValue/n+"\n");
        System.out.println("There were "+n+" residual risks \n");
        System.out.println("\n");
		return residualRiskValues;
		
	}
	
	
	
	public Map<String, Float> potentialRiskCalculation(OWLOntology o, OWLOntologyManager man, OWLDataFactory dataFactory, String base, OWLReasoner reasoner, String base_DRM) {
		
		PrefixManager pmDRM = new DefaultPrefixManager(base_DRM + "#");
		PrefixManager pm = new DefaultPrefixManager(base + "#");

		Map<String, Float> pootentialRiskValues = new HashMap<String, Float>();
		float potentialRiskTotalValue = 0 ;
		int n=0;
		
		
		OWLClassExpression pr = dataFactory.getOWLClass(":PotentialRisk", pmDRM);
		System.out.println("La clase pr es: "+pr);
	
		Set<OWLNamedIndividual> setInstances = o.getIndividualsInSignature();
        for (OWLNamedIndividual i : setInstances) {
            
            if(isPotentialRisk(i, o, dataFactory, reasoner, base_DRM)) {
            	 OWLDataProperty pRisk = dataFactory.getOWLDataProperty(":potentialRisk", pm); 
            	 OWLDataProperty ptype = dataFactory.getOWLDataProperty(":type", pm);          
                 
                 //Valor de la propiedad actualRisk (7.0)
             
         	    String s = obtainDataPropertyValue(i, pRisk, o, reasoner);
         	    if(!s.isEmpty()) {
         		   float d_float = Float.parseFloat(s);
         		   potentialRiskTotalValue = potentialRiskTotalValue + d_float;
             	   System.out.println(potentialRiskTotalValue);
             	  String type = obtainDataPropertyValue(i, ptype, o, reasoner);
             	  pootentialRiskValues.put(type, d_float);
         	    }
         	    n++;
    			

            }     
        }
            
        
        System.out.println("The potential risk total value is : "+potentialRiskTotalValue/n+"\n");
        System.out.println("There were "+n+" potential risks \n");
        System.out.println("\n");
		return pootentialRiskValues;
	}
	
	public void riesgoIndividual(OWLOntology o, OWLOntologyManager man, OWLDataFactory dataFactory, String base, OWLReasoner reasoner, String base_DRM, OWLClass riesgo) {
		PrefixManager pmDRM = new DefaultPrefixManager(base_DRM + "#");
		
		
		
		
	}
	
	public void riesgoTotal(Map<String, Float> m, OWLOntology o, OWLOntologyManager man, OWLDataFactory dataFactory, String base, OWLReasoner reasoner, String base_DRM) {
		
		
		
	}
	
}
