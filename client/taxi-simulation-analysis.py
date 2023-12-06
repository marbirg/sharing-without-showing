import json
import statistics
import matplotlib.pyplot as plt
import matplotlib.cm as cm
import numpy as np
# Recorded results files:
recorded_data = {
    100: 'recorded_simulation_data/taxi-simulation-100-20231205-163237.json',
    1000:'recorded_simulation_data/taxi-simulation-1000-20231205-162302.json',
    2000:'recorded_simulation_data/taxi-simulation-2000-20231205-155052.json',
    3000:'recorded_simulation_data/taxi-simulation-3000-20231205-151508.json',
    4000:'recorded_simulation_data/taxi-simulation-4000-20231205-145816.json',
    5000:'recorded_simulation_data/taxi-simulation-5000-20231205-143444.json',
    }

def read_data(fname):
    with open(fname, "r") as openfile:
        data = json.load(openfile)
    return data

def get_distribution_time(data):
    comp_time = []
    deploy_time = []
    for d in data:
        comp_time.append(d['distribution_time']['comp'])
        deploy_time.append(d['distribution_time']['deploy'])

    mean_deploy = statistics.mean(deploy_time)
    mean_comp = statistics.mean(comp_time)

    return comp_time, deploy_time, mean_deploy, mean_comp, len(deploy_time)

def print_computation_time():
    n_taxis = [100, 1000, 2000, 3000, 4000, 5000]

    for n in n_taxis:
        fname = recorded_data[n]
        data = read_data(fname)
        comp_time, deploy_time, mean_deploy, mean_comp, n_it = get_distribution_time(data)
        total = [x + y for x, y in zip(comp_time, deploy_time)]
        print(total)
        print(statistics.mean(total))
        std = statistics.stdev(total)

        print("Number of taxis:", n)
        print("Number of iterations:", n_it)
        print("Mean deploy time:", mean_deploy)
        print("Mean computation time:", mean_comp) 
        print("Sum:", mean_deploy+mean_comp)
        print("STD:", std)
        print("----------------")

def plot_computation_time():
    n_taxis = [100, 1000, 2000, 3000, 4000, 5000]

    comp = []
    deploy = []
    total = []
    for n in n_taxis:
        fname = recorded_data[n]
        data = read_data(fname)
        comp_time, deploy_time, mean_deploy, mean_comp, n_it = get_distribution_time(data)
        comp.append(mean_comp)
        deploy.append(mean_deploy)
        total.append(mean_comp+mean_deploy)

    plt.plot(n_taxis, comp, label='Computation')
    plt.plot(n_taxis, deploy, label='Data deployment')
    plt.plot(n_taxis, total, label='Total')
    plt.xlabel("Number of Taxis")
    plt.ylabel("Time [s]")

    plt.title("Taxi distribution computation time")
    plt.legend()
    plt.show()


def create_distribution_plot(distrubution, ax_max):
    # x = np.arange(0, math.pi*2, 0.05)
    fig = plt.figure()
    ax = fig.add_axes([0.1, 0.1, 0.8, 0.8]) # main axes
    # y = np.sin(x)

    fontsize = 12

    ticks = list(range(0,ax_max+1,100))
    N=len(distrubution)
    x = []
    y = []
    values = []
    area = []
    max_area = 50*50
    zone_colors = []
    for k,v in distrubution.items():
        # print(k[0], k[1],v)
        x.append(k[0])
        y.append(k[1])
        values.append(v)
        area.append(v*max_area/N)

    color_values = []
    for v in values:
        color_values.append(v/max(values))
    # ax.plot(x, y)
    
    # colors = cm.rainbow(np.linspace(0, 1, len(distrubution)))
    colors = cm.rainbow(color_values)
    ax.scatter(x,y,s=area, c=colors, alpha=0.5)
    # Annotate value
    for i in range(N):
        # print(i, (x[i], y[i]), str(values[i]))
        # plt.text(x[i],y[i],str(values[i]), fontsize=fontsize, ha='center', va='center') 
        ax.text(x[i],y[i],str(values[i]), ha='center', va='center', fontsize=fontsize) 

    ax.set_xticks(ticks)
    ax.set_yticks(ticks)
    # ax.set_xticks([0,500, 900])
    
    ax.grid()
    # ax.set_xticklabels(['zero','two','four','six'])
    # ax.set_yticks([-1,0,1])
    plt.title("Taxi distribution")
    plt.show()

def create_distribution_plot_old(distrubution,ax_max):
    fig = plt.figure()

    lim_offset=5
    N=len(distrubution)
    # colors = np.random.rand(N)
    colors = cm.rainbow(np.linspace(0, 1, len(distrubution)))

    ticks = list(range(0,ax_max+1,100))
    print(ax_max)
    ax = fig.add_axes([0,ax_max+1, 0, ax_max+1])

    fontsize = 12
    # ax.scatter(x_pos, y_pos, c=colors)
    x = []
    y = []
    values = []
    area = []
    max_area = 50*50
    zone_colors = []
    # print("Colors:", colors)
    for k,v in distrubution.items():
        # print(k[0], k[1],v)
        x.append(k[0])
        y.append(k[1])
        values.append(v)
        area.append(v*max_area/N)
        # c = colors[(k[0],k[1])]
        # plot("Zone color:",c)
        
        # zone_colors.append(colors[(k[0],k[1])])
        
    # ax.scatter(x, y, s=area, c=zone_colors, alpha=0.5)
    ax.scatter(x, y, s=area, alpha=0.5)

    # Annotate value
    # for i in range(N):
        # print(i, (x[i], y[i]), str(values[i]))
        # plt.text(x[i],y[i],str(values[i]), fontsize=fontsize, ha='center', va='center') 
        # ax.text(x[i],y[i],str(values[i]), fontsize=fontsize, ha='center', va='center') 

    # ax.set_xticks(ticks)
    # ax.set_yticks(ticks)
    # ax.grid()
    # plt.set_xlim([map.MIN_X-lim_offset,map.MAX_X+lim_offset])
    # plt.set_ylim([map.MIN_Y-lim_offset,map.MAX_Y+lim_offset])
    plt.show()

def plot_distribution():
    n=5000
    time_step = 0
    fname = recorded_data[n]
    data = read_data(fname)
    data = data[time_step]

    dist = data['distribution']
    distribution = {}
    for zone in range(len(dist)):
        if dist[zone]==0:
            continue
        # print("zone:",zone, 'taxis:', result[zone])
        zx = zone//10
        zy = zone%10
        # print("Zone coord:", zx,zy)
        center = (zx*100+50, zy*100+50)
        # print("Center coord:", center)
        distribution[center]=dist[zone]

    create_distribution_plot(distribution,1000, )
    
    
import math
def test():
    x = np.arange(0, math.pi*2, 0.05)
    fig = plt.figure()
    ax = fig.add_axes([0.1, 0.1, 0.8, 0.8]) # main axes
    y = np.sin(x)
    # ax.plot(x, y)
    ax.scatter(x,y)
    ax.set_xlabel('angle')
    ax.set_title('sine')
    ax.set_xticks([0,2,4,6])
    ax.set_xticklabels(['zero','two','four','six'])
    ax.set_yticks([-1,0,1])
    plt.show()

def main():
    print_computation_time()
    # plot_computation_time()
    # plot_distribution()
    # test()

if __name__=='__main__':
    main()
