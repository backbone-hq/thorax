fn main() -> Result<(), Box<dyn std::error::Error>> {
    for crd in thorax_kubernetes_api::crds() {
        println!("---");
        print!("{}", serde_yaml::to_string(&crd)?);
    }
    Ok(())
}
