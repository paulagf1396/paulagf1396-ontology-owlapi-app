package owl.upm.cyberthreat.owlapi;

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.Reader;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.json.simple.JSONObject;
import org.jfree.chart.ChartFactory;
import org.jfree.chart.ChartPanel;
import org.jfree.chart.JFreeChart;
import org.jfree.chart.plot.PiePlot3D;
import org.jfree.data.general.DefaultPieDataset;
import org.jfree.data.general.PieDataset;
import org.jfree.util.Rotation;
import org.json.simple.JSONArray;
import org.json.simple.parser.JSONParser;
import org.json.simple.parser.ParseException;
import org.junit.Test;
import org.mindswap.pellet.PelletOptions;
import org.semanticweb.owlapi.apibinding.OWLManager;
import org.semanticweb.owlapi.formats.FunctionalSyntaxDocumentFormat;
import org.semanticweb.owlapi.formats.PrefixDocumentFormat;
import org.semanticweb.owlapi.io.SystemOutDocumentTarget;
import org.semanticweb.owlapi.model.IRI;
import org.semanticweb.owlapi.model.OWLAxiom;
import org.semanticweb.owlapi.model.OWLClass;
import org.semanticweb.owlapi.model.OWLClassAssertionAxiom;
import org.semanticweb.owlapi.model.OWLClassExpression;
import org.semanticweb.owlapi.model.OWLDataAllValuesFrom;
import org.semanticweb.owlapi.model.OWLDataFactory;
import org.semanticweb.owlapi.model.OWLDataProperty;
import org.semanticweb.owlapi.model.OWLDataPropertyAssertionAxiom;
import org.semanticweb.owlapi.model.OWLDataRange;
import org.semanticweb.owlapi.model.OWLEntity;
import org.semanticweb.owlapi.model.OWLIndividual;
import org.semanticweb.owlapi.model.OWLLiteral;
import org.semanticweb.owlapi.model.OWLNamedIndividual;
import org.semanticweb.owlapi.model.OWLObjectProperty;
import org.semanticweb.owlapi.model.OWLObjectPropertyAssertionAxiom;
import org.semanticweb.owlapi.model.OWLOntology;
import org.semanticweb.owlapi.model.OWLOntologyCreationException;
import org.semanticweb.owlapi.model.OWLOntologyIRIMapper;
import org.semanticweb.owlapi.model.OWLOntologyManager;
import org.semanticweb.owlapi.model.OWLOntologyStorageException;
import org.semanticweb.owlapi.model.OWLSignature;
import org.semanticweb.owlapi.model.OWLSubClassOfAxiom;
import org.semanticweb.owlapi.model.PrefixManager;
import org.semanticweb.owlapi.reasoner.Node;
import org.semanticweb.owlapi.reasoner.NodeSet;
import org.semanticweb.owlapi.reasoner.OWLReasoner;
import org.semanticweb.owlapi.reasoner.OWLReasonerConfiguration;
import org.semanticweb.owlapi.reasoner.OWLReasonerFactory;
import org.semanticweb.owlapi.reasoner.ReasonerProgressMonitor;
import org.semanticweb.owlapi.reasoner.SimpleConfiguration;
import org.semanticweb.owlapi.reasoner.impl.OWLClassNode;
import org.semanticweb.owlapi.util.DefaultPrefixManager;
import org.semanticweb.owlapi.util.InferredAxiomGenerator;
import org.semanticweb.owlapi.util.InferredOntologyGenerator;
import org.semanticweb.owlapi.util.InferredSubClassAxiomGenerator;
import org.semanticweb.owlapi.util.PriorityCollection;
import org.semanticweb.owlapi.util.Version;
import org.swrlapi.core.SWRLAPIRule;
import org.swrlapi.core.SWRLRuleEngine;
import org.swrlapi.exceptions.SWRLBuiltInException;
import org.swrlapi.factory.SWRLAPIFactory;
import org.swrlapi.parser.SWRLParseException;

import com.clarkparsia.pellet.owlapiv3.PelletReasoner;
import com.clarkparsia.pellet.owlapiv3.PelletReasonerFactory;
import com.google.common.base.Optional;
import com.google.gson.Gson;
import com.google.gson.GsonBuilder;
import com.google.gson.JsonArray;
import com.google.gson.JsonElement;
import com.google.gson.JsonObject;
import com.google.gson.JsonParser;



public class OntologyApp {

	private static String base;
	private static IRI documentIRI;
	private static int loadedAnomalyInstances;
	private static Anomaly anomaly;
	private static DRM drm;
	private static STIX stix;
	public static  Map<String, Float> dataset;
	private static Chart chart;
	
	public OntologyApp() {
		
	}
	private static void saveOntologyinFile(OWLOntologyManager man, OWLOntology o) throws OWLOntologyCreationException, OWLOntologyStorageException, FileNotFoundException {
		
		File fileout = new File("./owl-files/example0.owl");
		man.saveOntology(o, new FunctionalSyntaxDocumentFormat(),new FileOutputStream(fileout));
		System.out.println("Saving ontology...");
	}
	
	 
	public int loadAnomaliesFromBBDD (OWLOntology o, OWLOntologyManager man, String fileAnomaliesJSON, String base, OWLDataFactory dataFactory) throws IOException, ParseException {
		
		int numInstances = 0;
		//if the file is empty, returns 0	
		if(fileAnomaliesJSON.isEmpty()) {
			return 0;
		}		
		JSONParser jsonParser = new JSONParser();
		System.out.println("loading JSON file...\n");
		FileReader reader = new FileReader("./owl-files/ficheroJSONSensores.json");

		//loadinf JSONObject...
		Object obj = jsonParser.parse(reader);
		//Loading JSONArray
		JSONArray dataList = (JSONArray) obj;
		System.out.println("JSONObject List obtained from file:\n");
        System.out.println(dataList);
        
        //The instances are loaded to the corresponding class
        for(int i = 0; i< dataList.size(); i++) {
        	JSONObject jObject = (JSONObject) dataList.get(i); 
        	if(jObject.get("anomaly").toString().equals("1") ) {
        		//If anomaly=1 means that there has been an anomaly. 0 means there hasnt been any.
        		OWLIndividual anomaly_instance = dataFactory.getOWLNamedIndividual(IRI.create(base +"#"+"Anomalia"+i));
        		anomaly.loadAnomalyInstances(man,anomaly_instance,o, dataFactory, jObject);	
        		numInstances++;
        	}else {
        		//Amenazas y Riesgos
        	}
        	
        }
        reader.close();
        return numInstances;
		
	}

	//Crear individuals
	public void createIndividuals(OWLOntology o, OWLOntologyManager man, OWLDataFactory dataFactory, String base, String cls, String individualName, int isType) throws OWLOntologyStorageException {
		
		//Anomaly=2, DRM = 1 , STIX = 0
		
		if(isType ==0) {
			stix.createSTIXInstances(man, o, dataFactory, cls, individualName);
		}
		else if(isType==1){
			
			drm.createDRMInstances(man, o, dataFactory, cls, individualName);
			
		}else if(isType==2){
			anomaly.createAnomalyInstances(man, o, dataFactory, cls, individualName);
		}else {
			System.out.println("The ontology type selected does not exist");
		}
		man.saveOntology(o);
	}
	
	//Crear Data Properties
	public void createDataProperty(OWLOntology o, OWLOntologyManager man, OWLDataFactory dataFactory, String base, String object, String property, String value) {
		PrefixManager pm = new DefaultPrefixManager(base + "#");
		
		OWLDataProperty dproperty = dataFactory.getOWLDataProperty(":"+property, pm);
		OWLIndividual instance = dataFactory.getOWLNamedIndividual(IRI.create(base +"#"+object));
		OWLDataPropertyAssertionAxiom dAxiom = dataFactory.getOWLDataPropertyAssertionAxiom(dproperty, instance, value);
		man.addAxiom(o, dAxiom);
	}
	
	//Crear Object Properties
	public void createObjectProperty(OWLOntology o, OWLOntologyManager man, OWLDataFactory dataFactory, String base, String object1, String object2, String property) {
		PrefixManager pm = new DefaultPrefixManager(base + "#");
		
		OWLObjectProperty oproperty = dataFactory.getOWLObjectProperty(":"+property, pm);
		OWLIndividual instance1 = dataFactory.getOWLNamedIndividual(IRI.create(base +"#"+object1));
		OWLIndividual instance2 = dataFactory.getOWLNamedIndividual(IRI.create(base +"#"+object2));

		OWLObjectPropertyAssertionAxiom oAxiom = dataFactory.getOWLObjectPropertyAssertionAxiom(oproperty, instance1, instance2);
		man.addAxiom(o, oAxiom);
	}
	
	//Load Pellet Reasoner
	public void loadReasoner(OWLOntology o, OWLOntologyManager man, OWLDataFactory dataFactory, String base) throws OWLOntologyStorageException {
		
		OWLReasonerFactory reasonerFactory = PelletReasonerFactory.getInstance();
		PelletReasoner reasoner =  (PelletReasoner) reasonerFactory.createReasoner(o);
		System.out.println(PelletOptions.IGNORE_UNSUPPORTED_AXIOMS);
		PelletOptions.IGNORE_UNSUPPORTED_AXIOMS = false;
		System.out.println(PelletOptions.IGNORE_UNSUPPORTED_AXIOMS);
		
		System.out.println("Using reasoner: "+ reasoner.getReasonerName());
		System.out.println("The ontology consistency is "+reasoner.isConsistent());
		System.out.println("Executing rules...");
		reasoner.getKB().realize();
		reasoner.precomputeInferences();
		System.out.println("**********************Class tree**********************");
		reasoner.getKB().printClassTree();
		System.out.println("******************************************************");
		System.out.println("Loading infered axioms to the ontology...");
		loadInferedAxiomsByReasoner(o, man, dataFactory, base, reasoner);
		System.out.println("Done.");
		
		System.out.println("Dynamic Risk Calculation");
		dynamicRiskCalculation(o, man, dataFactory, base, reasoner);
		

	}
	public void loadInferedAxiomsByReasoner(OWLOntology o, OWLOntologyManager man, OWLDataFactory dataFactory, String base, OWLReasoner reasoner) throws OWLOntologyStorageException {

		//What was inferred is written to the ontology
        List<InferredAxiomGenerator<? extends OWLAxiom>> gens = new ArrayList<InferredAxiomGenerator<? extends OWLAxiom>>();
        gens.add(new InferredSubClassAxiomGenerator());

        //Create the inferred ontology generator
        InferredOntologyGenerator iog = new InferredOntologyGenerator(reasoner, gens);
        iog.fillOntology(dataFactory, o);
        
        man.saveOntology(o);
        
	}
	
	
	//Load SWRL rules engine
	public void loadSWRLRuleENgine(OWLOntology o, OWLOntologyManager man, OWLDataFactory dataFactory, String base) throws SWRLParseException, SWRLBuiltInException, OWLOntologyStorageException {
		
		
		 // Create a SWRL rule engine using the SWRLAPI
		 SWRLRuleEngine swrlRuleEngine = SWRLAPIFactory.createSWRLRuleEngine(o);
	 
		 // Run the SWRL rules in the ontology
		 swrlRuleEngine.infer();
		
		 //Sino guardo la ontologia no se guarda lo generado por las reglas
		 man.saveOntology(o);
		 System.out.println("Ontology saved.");
	}
	
	public Map<String, Float> dynamicRiskCalculation(OWLOntology o, OWLOntologyManager man, OWLDataFactory dataFactory, String base, OWLReasoner reasoner) {
		String base_DRM = "http://www.semanticweb.org/upm/ontologies/2019/11/cyberthreat_DRM";
		PrefixManager pmDRM = new DefaultPrefixManager(base_DRM + "#");
		PrefixManager pm = new DefaultPrefixManager(base + "#");

		OWLClass rr = dataFactory.getOWLClass(":ResidualRisk", pmDRM);
		float residualRiskTotalValue = 0 ;
		int n=0;
		NodeSet<OWLNamedIndividual> instances = reasoner.getInstances(rr, true);
		Set<OWLNamedIndividual> setInstances = instances.getFlattened();
        System.out.println("Subclasses of ResidualRisk: ");
        for (OWLNamedIndividual cls : setInstances) {
            System.out.println("    " + cls);
            OWLDataProperty actualRisk = dataFactory.getOWLDataProperty(":actualRisk", pmDRM);            
            Set<OWLLiteral> dp = reasoner.getDataPropertyValues(cls, actualRisk);
            for (OWLLiteral d :dp) {
        	  //Valor de la propiedad actualRisk (7.0)
        	   String s = d.getLiteral();
        	   float d_float = Float.parseFloat(s);
        	   residualRiskTotalValue = residualRiskTotalValue + d_float;
        	   System.out.println(residualRiskTotalValue);
        	   dataset.put(cls.toString(), d_float);
            }
            //Valor de todo al completo ["7.0"^^xsd:float] (esto es un set), por tanto hay que hacer un for
            n++;
        }
        System.out.println("The residual risk total value is : "+residualRiskTotalValue/n);
        System.out.println("\n");
		return dataset;
		
	}
	
	
	public static void main(String[] args) throws OWLOntologyCreationException, IOException, ParseException, SWRLParseException, SWRLBuiltInException, OWLOntologyStorageException {
		OntologyApp onto_object =new OntologyApp();
		
		System.out.println("");
		System.out.println("Loading Ontology...");
		File file = new File("./owl-files/cibersituational-onto.owl");
		OWLOntologyManager man = OWLManager.createOWLOntologyManager();
		OWLOntology o =  man.loadOntologyFromOntologyDocument(file);
		documentIRI = o.getOntologyID().getOntologyIRI().get();
		base = documentIRI.toString();
		System.out.println("Ontology loaded\n");
		

		
		OWLDataFactory dataFactory = man.getOWLDataFactory();
		anomaly= new Anomaly(dataFactory, man, base);
		drm= new DRM(dataFactory, man, base);
		stix = new STIX(dataFactory, man, base);
		chart = new Chart(o, man, dataFactory, "Riesgo Residual de cada Riesgo", dataset);

		//File to load information
		System.out.println("Loading data into the ontology...\n");
		File fileAnomalies = new File("./owl-files/ficheroJSONSensores.json");
		String fileAnomaliesJSON = fileAnomalies.toString();
		loadedAnomalyInstances = onto_object.loadAnomaliesFromBBDD(o, man, fileAnomaliesJSON, base, dataFactory);
		System.out.println("There have been loaded "+loadedAnomalyInstances+ " instances of new anomalies\n");
		
		//Cargar rules
		//System.out.println("Loading rules...\n");
		//onto_object.loadSWRLRuleENgine(o, man, dataFactory, base);
		
		//Cargar razonador
		//System.out.println("Starting the reasoner...\n");
		//onto_object.loadReasoner(o, man, dataFactory, base);
		
		

		
		
	}

}
