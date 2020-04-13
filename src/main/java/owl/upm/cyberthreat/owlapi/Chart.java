package owl.upm.cyberthreat.owlapi;

import java.util.Map;

import org.jfree.chart.ChartFactory;
import org.jfree.chart.ChartFrame;
import org.jfree.chart.JFreeChart;
import org.jfree.data.general.DefaultPieDataset;
import org.semanticweb.owlapi.model.OWLDataFactory;
import org.semanticweb.owlapi.model.OWLOntology;
import org.semanticweb.owlapi.model.OWLOntologyManager;

public class Chart {
	 
	private DefaultPieDataset data;
	
	public Chart(OWLOntology o, OWLOntologyManager man, OWLDataFactory dataFactory, String title, Map<String, Float> dataset) {
		
		data = new DefaultPieDataset();
	
		
		
	}
    public static void main(String[] args) {
        // create a dataset...
        DefaultPieDataset data = new DefaultPieDataset();
        data.setValue("Category 1", 43.2);
        data.setValue("Category 2", 27.9);
        data.setValue("Category 3", 79.5);
        // create a chart...
        JFreeChart chart = ChartFactory.createPieChart("Example", data, true, true, false);
        // create and display a frame...
        ChartFrame frame = new ChartFrame("First", chart);
        frame.pack();
        frame.setVisible(true);
    }

}
