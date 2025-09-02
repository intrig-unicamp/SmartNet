from sftopo import SFTopo

def main():
    topo = SFTopo()

    # Define topology
    topo.add_switch("s1")
    topo.add_switch("s2")
    topo.add_switch("s3")
    topo.add_switch("s4")

    # Add links
    topo.add_link("s1", "s2", bandwidth=0, latency=10, jitter=5)
    topo.add_link("s2", "s3")
    topo.add_link("s3", "s4")
    topo.add_link("s1", "p0", link_type="physical")  # External connection
    topo.add_link("s4", "p1", link_type="physical")  # External connection

    # Show topology in console
    topo.show_topology()

    # Show topology as a graphical visualization
    #topo.visualize_topology()
    
    topo.start()

if __name__ == "__main__":
    main()
