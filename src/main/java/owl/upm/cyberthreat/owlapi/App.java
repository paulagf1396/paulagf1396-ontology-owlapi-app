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

/**
 * Hello world!
 *
 */
public class App 
{
	
	
	
	//Load ontology
	public static void main(String[] args) throws OWLOntologyCreationException, OWLOntologyStorageException, FileNotFoundException {
		OWLOntologyManager man = OWLManager.createOWLOntologyManager();
		File file = new File("./owl-files/ontologias_merged_backup.owl");
		OWLOntology o = man.loadOntologyFromOntologyDocument(file);
		System.out.println(o);
		
		//save
		//File fileout = new File("./owl-files/ontologias_merged_v1.0.owl");
		//man.saveOntology(o, new FunctionalSyntaxDocumentFormat(),new FileOutputStream(fileout));
		
        // List of classes
        System.out.print("{");
        for (Iterator<OWLClass> it = o.getClassesInSignature().iterator(); it.hasNext();) {
            OWLClass cls = it.next();
            System.out.print(cls);
            if (it.hasNext()) {
                System.out.print(" \n");
            }
        }
        System.out.println("}");
        
        //List of dataProperties
        System.out.print("{");
        for (Iterator<OWLDataProperty> it = o.getDataPropertiesInSignature().iterator(); it.hasNext();) {
        	OWLDataProperty cls = it.next();
            System.out.print(cls);
            if (it.hasNext()) {
                System.out.print(" \n");
            }
        }
        System.out.println("}");
	}

}
