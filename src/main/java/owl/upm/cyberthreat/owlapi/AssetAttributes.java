package owl.upm.cyberthreat.owlapi;

import java.util.List;

import com.opencsv.bean.CsvBindByPosition;

public class AssetAttributes {
		

    @CsvBindByPosition(position = 0)
    private String name;

    @CsvBindByPosition(position = 1)
    private String type;

    @CsvBindByPosition(position = 2)
    private String porcentaje;

    @CsvBindByPosition(position = 3)
    private List dependencies;

   

    public AssetAttributes(String name, String type, String porcentaje, List dependencies) {
        this.name = name;
        this.type = type;
        this.porcentaje = porcentaje;
        this.dependencies = dependencies;
    }



	public String getName() {
		return name;
	}



	public void setName(String name) {
		this.name = name;
	}



	public String getType() {
		return type;
	}



	public void setType(String type) {
		this.type = type;
	}



	public String getPorcentaje() {
		return porcentaje;
	}



	public void setPorcentaje(String porcentaje) {
		this.porcentaje = porcentaje;
	}



	public List getDependencies() {
		return dependencies;
	}



	public void setDependencies(List dependencies) {
		this.dependencies = dependencies;
	}
	
	
}
