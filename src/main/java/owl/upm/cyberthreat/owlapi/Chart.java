package owl.upm.cyberthreat.owlapi;

import java.awt.BasicStroke;
import java.awt.Color;
import java.awt.Font;
import java.io.IOException;
import java.util.Map;
import java.util.Map.Entry;

import javax.swing.BorderFactory;
import javax.swing.JFrame;

import org.jfree.chart.ChartFactory;
import org.jfree.chart.ChartFrame;
import org.jfree.chart.ChartPanel;
import org.jfree.chart.JFreeChart;
import org.jfree.chart.block.BlockBorder;
import org.jfree.chart.plot.PlotOrientation;
import org.jfree.chart.plot.XYPlot;
import org.jfree.chart.renderer.xy.XYLineAndShapeRenderer;
import org.jfree.chart.title.TextTitle;
import org.jfree.data.category.CategoryDataset;
import org.jfree.data.category.DefaultCategoryDataset;
import org.jfree.data.general.DefaultPieDataset;
import org.jfree.data.statistics.HistogramDataset;
import org.jfree.data.statistics.HistogramType;
import org.jfree.data.xy.XYDataset;
import org.jfree.data.xy.XYSeries;
import org.jfree.data.xy.XYSeriesCollection;
import org.semanticweb.owlapi.model.OWLDataFactory;
import org.semanticweb.owlapi.model.OWLOntology;
import org.semanticweb.owlapi.model.OWLOntologyManager;

public class Chart {
	 
	
	public Map<String, Float> dataset1;
	public Map<String, Float> dataset2;
	
	public Chart(Map<String, Float> dataset1, Map<String, Float> dataset2) {
		
		this.dataset1 = dataset1;
		this.dataset2 = dataset2;
	
		
		
	}
	
	public void barchartPaint(String rr, String pr) {

		DefaultCategoryDataset data = new DefaultCategoryDataset();
		for (Entry<String, Float> entry : dataset1.entrySet()) {
			String name= null;
			float valor = 0;
			name = entry.getKey();
			//name = name.substring(name.indexOf("#") + 1, name.length() -1);
			valor = entry.getValue();
			data.setValue(valor, rr, name);	
			
		}
		for (Entry<String, Float> entry : dataset2.entrySet()) {
			String name= null;
			float valor = 0;
			name = entry.getKey();
			//name = name.substring(name.indexOf("#") + 1, name.length() -1);
			valor = entry.getValue();
			data.setValue(valor, pr, name);	
			
		}
		String plotTitle = "Historgram"; 
		String xaxis = "number";
		String yaxis = "value"; 
		JFreeChart barChart = ChartFactory.createBarChart(
                "Residual/Potential Risks",
                "Risks",
                "Risk Value",
                data,
                PlotOrientation.VERTICAL,
                false, true, false);
        ChartFrame frame = new ChartFrame("First", barChart);
		frame.pack();
		frame.setVisible(true);
		
	}
	
	
    private void initUI() {

        XYDataset dataset = createDataset();
        JFreeChart chart = createChart(dataset);
        ChartPanel chartPanel = new ChartPanel(chart);
        chartPanel.setBorder(BorderFactory.createEmptyBorder(15, 15, 15, 15));
        chartPanel.setBackground(Color.white);
        
       
    }

    private static XYDataset createDataset() {

        XYSeries series1 = new XYSeries("2014");
        series1.add(18, 530);
        series1.add(20, 580);
        series1.add(25, 740);
        series1.add(30, 901);
        series1.add(40, 1300);
        series1.add(50, 2219);

        XYSeries series2 = new XYSeries("2016");
        series2.add(18, 567);
        series2.add(20, 612);
        series2.add(25, 800);
        series2.add(30, 980);
        series2.add(40, 1210);
        series2.add(50, 2350);

        XYSeriesCollection dataset = new XYSeriesCollection();
        dataset.addSeries(series1);
        dataset.addSeries(series2);

        return dataset;
    }

    private static JFreeChart createChart(final XYDataset dataset) {

        JFreeChart chart = ChartFactory.createXYLineChart(
                "Average salary per age",
                "Age",
                "Salary (€)",
                dataset,
                PlotOrientation.VERTICAL,
                true,
                true,
                false
        );

        XYPlot plot = chart.getXYPlot();

        XYLineAndShapeRenderer renderer = new XYLineAndShapeRenderer();

        renderer.setSeriesPaint(0, Color.RED);
        renderer.setSeriesStroke(0, new BasicStroke(2.0f));
        renderer.setSeriesPaint(1, Color.BLUE);
        renderer.setSeriesStroke(1, new BasicStroke(2.0f));

        plot.setRenderer(renderer);
        plot.setBackgroundPaint(Color.white);
        plot.setRangeGridlinesVisible(false);
        plot.setDomainGridlinesVisible(false);

        chart.getLegend().setFrame(BlockBorder.NONE);

        chart.setTitle(new TextTitle("Average Salary per Age",
                        new Font("Serif", Font.BOLD, 18)
                )
        );

        return chart;
    }
    public static void main(String[] args) {
   	 XYDataset dataset = createDataset();
        JFreeChart chart = createChart(dataset);
        ChartPanel chartPanel = new ChartPanel(chart);
        chartPanel.setBorder(BorderFactory.createEmptyBorder(15, 15, 15, 15));
         
        chartPanel.setBackground(Color.white);
        ChartFrame frame = new ChartFrame("First", chart);
        frame.add(chartPanel);

       
        frame.setTitle("Line chart");
        frame. setLocationRelativeTo(null);
        frame.setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		frame.pack();
		frame.setVisible(true);
    }

}
