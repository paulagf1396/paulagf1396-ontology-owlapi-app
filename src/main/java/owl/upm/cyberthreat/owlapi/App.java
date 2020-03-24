package owl.upm.cyberthreat.owlapi;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Set;
import java.util.stream.Stream;

import org.semanticweb.owlapi.apibinding.OWLManager;
import org.semanticweb.owlapi.formats.FunctionalSyntaxDocumentFormat;
import org.semanticweb.owlapi.model.IRI;
import org.semanticweb.owlapi.model.OWLClass;
import org.semanticweb.owlapi.model.OWLClassExpression;
import org.semanticweb.owlapi.model.OWLDataFactory;
import org.semanticweb.owlapi.model.OWLDataProperty;
import org.semanticweb.owlapi.model.OWLDeclarationAxiom;
import org.semanticweb.owlapi.model.OWLObject;
import org.semanticweb.owlapi.model.OWLObjectPropertyRangeAxiom;
import org.semanticweb.owlapi.model.OWLOntology;
import org.semanticweb.owlapi.model.OWLOntologyCreationException;
import org.semanticweb.owlapi.model.OWLOntologyFormat;
import org.semanticweb.owlapi.model.OWLOntologyManager;
import org.semanticweb.owlapi.model.OWLOntologyStorageException;
import org.semanticweb.owlapi.model.OWLSubClassOfAxiom;
import org.semanticweb.owlapi.reasoner.ConsoleProgressMonitor;
import org.semanticweb.owlapi.reasoner.NodeSet;
import org.semanticweb.owlapi.reasoner.OWLReasoner;
import org.semanticweb.owlapi.reasoner.OWLReasonerConfiguration;
import org.semanticweb.owlapi.reasoner.OWLReasonerFactory;
import org.semanticweb.owlapi.reasoner.SimpleConfiguration;
import org.semanticweb.owlapi.reasoner.structural.StructuralReasonerFactory;

/**
 * Hello world!
 *
 */
public class App 
{
	
	private static File file = new File("./owl-files/cyberthreat_ONA.owl");
	private static OWLOntologyManager man = OWLManager.createOWLOntologyManager();
	private static IRI DOCUMENTIRI;
	
	private static void listClasses() throws OWLOntologyCreationException {
		OWLOntology o = man.loadOntologyFromOntologyDocument(file);
		System.out.print("List of Classes \n");
        for (Iterator<OWLClass> it = o.getClassesInSignature().iterator(); it.hasNext();) {
            OWLClass cls = it.next();
            System.out.print(cls);
            if (it.hasNext()) {
                System.out.print(" \n");
            }
        }
        System.out.println("\n");
        
        //List of dataProperties
        System.out.print("List of Data properties");
        for (Iterator<OWLDataProperty> it = o.getDataPropertiesInSignature().iterator(); it.hasNext();) {
        	OWLDataProperty cls = it.next();
            System.out.print(cls);
            if (it.hasNext()) {
                System.out.print(" \n");
            }
        }
        System.out.println("\n");
	}
	/*
	private static void useReasoner() {
		OWLOntology o = (OWLOntology) man.loadOntologyFromOntologyDocument(file);
		//Pellet(http://clarkparsia.com/pellet)
		OWLDataFactory factory = man.getOWLDataFactory();
		
		//OWLReasonerFactory reasonerFactory = new Reasoner.ReasonerFactory();
		
		ConsoleProgressMonitor progressMonitor = new ConsoleProgressMonitor();
		OWLReasonerConfiguration config = new SimpleConfiguration(progressMonitor);
		//OWLReasoner reasoner = reasonerFactory.createReasoner(o, config);
		
		reasoner.precomputeInferences();
        // We can determine if the ontology is actually consistent (in this
        // case, it should be).
        boolean consistent = reasoner.isConsistent();
        System.out.println("Consistent: " + consistent);
        System.out.println("\n");
        
        //SUbclasses
        OWLDataFactory fac = man.getOWLDataFactory();
        OWLClass anomaly_type = fac.getOWLClass(IRI.create("DOCUMENTIRI#Anomaly_Type"));
        NodeSet<OWLClass> subClases = reasoner.getSubClasses(anomaly_type, true);
        Set<OWLClass> clases = subClases.getFlattened();
        System.out.println("Subclasses of vegetarian: ");
        for (OWLClass cls : clases) {
            System.out.println("    " + cls);
        }
        System.out.println("\n");
        
	}*/
	
	private static void saveOntology() throws OWLOntologyCreationException, OWLOntologyStorageException, FileNotFoundException {
		OWLOntology o = (OWLOntology) man.loadOntologyFromOntologyDocument(file);
		File fileout = new File("./owl-files/example0.owl");
		man.saveOntology(o, new FunctionalSyntaxDocumentFormat(),new FileOutputStream(fileout));
		System.out.println("Saving ontology...");
	}
	//Load ontology
	public static void main(String[] args) throws OWLOntologyCreationException, OWLOntologyStorageException, FileNotFoundException {
		OWLOntology o = (OWLOntology) man.loadOntologyFromOntologyDocument(file);
		DOCUMENTIRI = man.getOntologyDocumentIRI(o);
		System.out.println(DOCUMENTIRI);
		//save
		//saveOntology();
		
        // List of classes
		//listClasses();
        
		
	}

}
